"use server";

export async function previewUrl(formData: FormData) {
  const target = formData.get("url") as string;
  await fetch(target);
}
