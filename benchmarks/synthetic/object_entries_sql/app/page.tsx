import { inviteUser } from "./actions";

export default function Page() {
  return (
    <form action={inviteUser}>
      <input name="email" />
      <button type="submit">Invite</button>
    </form>
  );
}
