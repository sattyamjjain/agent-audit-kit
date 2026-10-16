export async function fetchDoc(url: string): Promise<string> {
  validateSafeUrl(url);
  const response = await fetch(url);
  return response.text();
}
