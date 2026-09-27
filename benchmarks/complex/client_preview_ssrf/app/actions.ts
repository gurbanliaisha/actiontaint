"use server";

import { fetchPreview } from "./http";

export async function refreshPreview(input: { url: string; cacheKey?: string }) {
  const html = await fetchPreview(input.url);
  return {
    cacheKey: input.cacheKey ?? "draft",
    html: html.slice(0, 120)
  };
}
