export async function handler(client: any, session_id: string) {
  await client.request({ method: "tools/list" });
  return session_id;
}
