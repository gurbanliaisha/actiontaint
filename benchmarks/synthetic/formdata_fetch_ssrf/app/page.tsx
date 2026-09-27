import { previewUrl } from "./actions";

export default function Page() {
  return (
    <form action={previewUrl}>
      <input name="url" />
      <button type="submit">Preview</button>
    </form>
  );
}
