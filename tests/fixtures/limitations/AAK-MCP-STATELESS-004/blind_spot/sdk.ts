export async function refresh(client: any, session_id: string) {
  await client.listTools();
  await client.listTools();
  return session_id;
}
