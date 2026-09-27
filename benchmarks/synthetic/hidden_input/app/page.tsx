import { readAttachment } from "./actions";

export default function Page() {
  return (
    <form action={readAttachment}>
      <input type="hidden" name="path" value="../../etc/passwd" />
      <button type="submit">Read</button>
    </form>
  );
}
