"use client";

import { useState } from "react";
import { refreshPreview } from "./actions";

export function PreviewButton() {
  const [url, setUrl] = useState("https://example.com");

  return (
    <section>
      <input value={url} onChange={(event) => setUrl(event.target.value)} />
      <button
        type="button"
        onClick={async () => {
          await refreshPreview({ url, cacheKey: "editor" });
        }}
      >
        Refresh
      </button>
    </section>
  );
}
