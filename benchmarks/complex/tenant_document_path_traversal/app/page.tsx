import { downloadTenantDocument } from "./actions";

type Props = {
  params: { tenantId: string };
};

export default function Page({ params }: Props) {
  const action = downloadTenantDocument.bind(null, params.tenantId);

  return (
    <form action={action}>
      <input name="document" defaultValue="invoice.pdf" />
      <button type="submit">Download</button>
    </form>
  );
}
