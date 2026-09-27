"use server";
import { db, prisma, supabase, cache, auth } from "./db";
import { redirect } from "next/navigation";
import { exec } from "child_process";
import axios from "axios";

// C01 arrow-function Server Action (TRUE SQLi)
export const arrowAction = async (formData: FormData) => {
  await db.query("SELECT * FROM t WHERE n = '" + formData.get("q") + "'");
};
// C02 RegExp.exec on user input (SAFE; FP risk: Command Injection)
export async function regexExec(formData: FormData) {
  const m = /^[a-z]+$/.exec(formData.get("name") as string);
  return m !== null;
}
// C03 Map.delete on user input (SAFE; FP risk: IDOR)
export async function mapDelete(formData: FormData) {
  cache.delete(formData.get("k") as string);
}
// C04 node-postgres object-form parameterized query (SAFE; FP risk: SQLi)
export async function pgObject(formData: FormData) {
  await db.query({ text: "SELECT * FROM t WHERE id = $1", values: [formData.get("id")] });
}
// C05 redirect to fixed internal prefix (SAFE; FP risk: Open Redirect)
export async function redirectPrefix(formData: FormData) {
  redirect("/posts/" + formData.get("id"));
}
// C06 fetch to fixed host (SAFE-ish; FP risk: SSRF)
export async function fetchFixedHost(formData: FormData) {
  await fetch("https://api.example.com/items/" + formData.get("id"));
}
// C07 ownership constraint built in a variable (SAFE; FP risk: IDOR)
export async function whereVar(formData: FormData) {
  const session = await auth();
  const where = { id: formData.get("id") as string, userId: session.user.id };
  await prisma.post.delete({ where });
}
// C08 Supabase delete without ownership (TRUE IDOR, README claims Supabase)
export async function supabaseDelete(formData: FormData) {
  await supabase.from("posts").delete().eq("id", formData.get("id"));
}
// C09 bare axios(url) (TRUE SSRF)
export async function axiosBare(formData: FormData) {
  await axios(formData.get("url") as string);
}
// C10 command injection (TRUE)
export async function cmd(formData: FormData) {
  exec("ls " + formData.get("dir"));
}
// C11 inline .bind in JSX with searchParams (TRUE SQLi via id)
export async function bindInline(id: string, formData: FormData) {
  await db.query("DELETE FROM t WHERE id = '" + id + "'");
}
// C12 never referenced by any client code (not reachable -> no finding expected by design)
export async function unusedAction(formData: FormData) {
  await db.query("SELECT " + formData.get("x"));
}
// C13 re-exported via separate export statement (TRUE SQLi)
async function reexported(formData: FormData) {
  await db.query("SELECT " + formData.get("x"));
}
export { reexported };
// C14 untyped parameter with non-standard name (TRUE SQLi)
export async function untypedParam(payload) {
  await db.query("SELECT " + payload.get("x"));
}
