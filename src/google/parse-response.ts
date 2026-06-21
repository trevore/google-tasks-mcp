/**
 * Read a fetch Response body as parsed JSON, treating 204 No Content and empty
 * bodies as success (null).
 *
 * Google Tasks DELETE (delete_task, delete_task_list) and the clear endpoint
 * return 204 with no body, so a bare `response.json()` throws "Unexpected end of
 * JSON input" — making a successful delete report a FALSE error to the agent.
 */
export async function parseResponseBody(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return null;
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}
