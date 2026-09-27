export async function fetchPreview(url: string) {
  const response = await fetch(url);
  return response.text();
}
