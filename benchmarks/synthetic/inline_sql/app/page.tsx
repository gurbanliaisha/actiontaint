import { db } from "./db";

export default function Page() {
  async function createPost(formData: FormData) {
    "use server";
    const title = formData.get("title") as string;
    await db.query("INSERT INTO posts(title) VALUES ('" + title + "')");
  }

  return (
    <form action={createPost}>
      <input name="title" />
      <button type="submit">Create</button>
    </form>
  );
}
