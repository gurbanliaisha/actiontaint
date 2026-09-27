import { updateTenant } from "./actions";

type Props = {
  searchParams: { tenant?: string };
};

export default function Page({ searchParams }: Props) {
  const updateForTenant = updateTenant.bind(null, searchParams.tenant);
  return (
    <form action={updateForTenant}>
      <input name="name" />
      <button type="submit">Update</button>
    </form>
  );
}
