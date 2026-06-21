import { Context } from "hono";

/**
 * The server's public base URL, honoring the reverse proxy (Caddy sets
 * X-Forwarded-Proto / Host). Behind the proxy the request arrives as
 * http://tasks:3000, so OAuth discovery metadata must use the forwarded
 * scheme/host to advertise https://gtasks.ellermann.net correctly.
 */
export function publicBaseUrl(c: Context): string {
  const url = new URL(c.req.url);
  const proto = c.req.header("X-Forwarded-Proto") || url.protocol.replace(":", "");
  const host = c.req.header("X-Forwarded-Host") || c.req.header("Host") || url.host;
  return `${proto}://${host}`;
}
