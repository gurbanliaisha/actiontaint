import { removeMember } from "./actions";

export default function Page() {
  return (
    <form action={removeMember}>
      <input type="hidden" name="memberId" value="member_999" />
      <button type="submit">Remove member</button>
    </form>
  );
}
