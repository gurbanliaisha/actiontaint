import { searchUsers } from "./actions";

export default function Page() {
  return (
    <form action={searchUsers}>
      <input name="term" />
      <button type="submit">Search</button>
    </form>
  );
}
