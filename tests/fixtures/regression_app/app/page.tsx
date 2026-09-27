import { arrowAction, regexExec, mapDelete, pgObject, redirectPrefix, fetchFixedHost, whereVar,
  supabaseDelete, axiosBare, cmd, bindInline, reexported, untypedParam } from "./actions";
import * as NS from "./ns/ns-actions";
import doDefault from "./default-action";
import { db } from "./db";

export default function Page({ searchParams }: { searchParams: { id: string; q: string } }) {
  // C17 inline Server Action closing over searchParams (TRUE SQLi)
  async function closureAction() {
    "use server";
    await db.query("SELECT * FROM t WHERE q = '" + searchParams.q + "'");
  }
  return (
    <div>
      <form action={arrowAction} />
      <form action={regexExec} />
      <form action={mapDelete} />
      <form action={pgObject} />
      <form action={redirectPrefix} />
      <form action={fetchFixedHost} />
      <form action={whereVar} />
      <form action={supabaseDelete} />
      <form action={axiosBare} />
      <form action={cmd} />
      <form action={bindInline.bind(null, searchParams.id)} />
      <form action={reexported} />
      <form action={untypedParam} />
      <form action={NS.nsAction} />
      <form action={doDefault} />
      <form action={closureAction} />
    </div>
  );
}
