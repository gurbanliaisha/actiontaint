"use client";

import { useActionState } from "react";
import { createUser } from "./actions";

export function SignupForm() {
  const [state, formAction] = useActionState(createUser, null);
  return (
    <form action={formAction}>
      <input name="email" />
      <button type="submit">Create</button>
    </form>
  );
}
