import { Context } from "hono";
import { RESPONSE_ALREADY_SENT } from "@hono/node-server/utils/response";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { registerAllTools } from "../tools/index.ts";
import { createLogger } from "../utils/logger.ts";

const logger = createLogger({ component: "mcp-endpoints" });

// Live MCP transports keyed by Mcp-Session-Id (in-memory; single process).
// The official StreamableHTTPServerTransport persists a session across the
// separate POSTs a client makes (initialize, then tools/list, etc.) and returns
// each request's response in that request's body — which the previous hand-rolled
// SSE-only transport did not, so Claude saw "no tools".
const transports: Record<string, StreamableHTTPServerTransport> = {};

// @hono/node-server exposes the raw Node req/res on c.env; the SDK transport
// writes directly to them, so we hand the response back with RESPONSE_ALREADY_SENT.
function nodeReqRes(c: Context) {
  return c.env as unknown as {
    incoming: import("node:http").IncomingMessage;
    outgoing: import("node:http").ServerResponse;
  };
}

export async function handleMcpPost(c: Context) {
  const mcpToken = c.get("mcpToken") as string;
  const sessionId = c.req.header("mcp-session-id");
  const body = await c.req.json();

  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports[sessionId]) {
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(body)) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        transports[sid] = transport;
        logger.info("MCP session initialized");
      },
    });
    transport.onclose = () => {
      if (transport.sessionId && transports[transport.sessionId]) {
        delete transports[transport.sessionId];
        logger.info("MCP session closed");
      }
    };

    const server = new McpServer(
      { name: "google-tasks-mcp", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    registerAllTools(server, mcpToken);
    await server.connect(transport);
  } else if (sessionId) {
    // Unknown/expired session (e.g. after a server restart) -> 404 so the client
    // re-initializes a fresh session instead of erroring (MCP spec behavior).
    return c.json(
      { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null },
      404,
    );
  } else {
    return c.json(
      { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: no valid session ID" }, id: null },
      400,
    );
  }

  const { incoming, outgoing } = nodeReqRes(c);
  await transport.handleRequest(incoming, outgoing, body);
  return RESPONSE_ALREADY_SENT as unknown as Response;
}

// GET = the optional server->client SSE stream for an established session.
export async function handleMcpGet(c: Context) {
  const sessionId = c.req.header("mcp-session-id");
  if (!sessionId || !transports[sessionId]) {
    return c.json(
      { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null },
      404,
    );
  }
  const { incoming, outgoing } = nodeReqRes(c);
  await transports[sessionId].handleRequest(incoming, outgoing);
  return RESPONSE_ALREADY_SENT as unknown as Response;
}

// DELETE = explicit session teardown.
export async function handleMcpDelete(c: Context) {
  const sessionId = c.req.header("mcp-session-id");
  if (!sessionId || !transports[sessionId]) {
    return c.json(
      { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null },
      404,
    );
  }
  const { incoming, outgoing } = nodeReqRes(c);
  await transports[sessionId].handleRequest(incoming, outgoing);
  return RESPONSE_ALREADY_SENT as unknown as Response;
}
