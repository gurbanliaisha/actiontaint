export const db = { async query(_q: unknown, _p?: unknown[]) { return []; } };
export const prisma = { post: { async delete(_a: unknown) { return {}; } } };
export const supabase = { from(_t: string) { return { delete() { return { eq(_c: string, _v: unknown) { return {}; } }; } }; } };
export const cache = new Map<string, string>();
export async function auth() { return { user: { id: "u1" } }; }
