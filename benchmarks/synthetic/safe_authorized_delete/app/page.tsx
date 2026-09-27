import { deletePost } from "./actions";

export default function Page() {
  return (
    <form action={deletePost}>
      <input name="postId" />
      <button type="submit">Delete</button>
    </form>
  );
}
