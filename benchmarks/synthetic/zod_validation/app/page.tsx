import { saveProfile } from "./actions";

export default function Page() {
  return (
    <form action={saveProfile}>
      <input name="username" />
      <button type="submit">Save</button>
    </form>
  );
}
