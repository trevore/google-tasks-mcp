import { test } from "node:test";
import assert from "node:assert/strict";
import { parseResponseBody } from "./parse-response.ts";

test("204 No Content resolves to null without throwing (the delete_task bug)", async () => {
  assert.equal(await parseResponseBody(new Response(null, { status: 204 })), null);
});

test("empty 200 body resolves to null", async () => {
  assert.equal(await parseResponseBody(new Response("", { status: 200 })), null);
});

test("a JSON body is parsed and returned", async () => {
  const r = new Response(JSON.stringify({ id: "x", title: "t" }), { status: 200 });
  assert.deepEqual(await parseResponseBody(r), { id: "x", title: "t" });
});
