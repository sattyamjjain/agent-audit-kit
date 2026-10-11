export async function refresh(client: any, session_id: string) {
  await client.request({ method: "tools/list" });
  await client.request({ method: "tools/list" });
  return session_id;
}
