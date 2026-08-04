/**
 * Build a Content-Disposition value that untrusted text cannot escape.
 *
 * Session ids reach these routes from recorded agent events, which this product
 * treats as attacker-controlled by design. Interpolated straight into a quoted
 * filename, an id containing a double quote closes the parameter and opens
 * another:
 *
 *     attachment; filename="session-x"; filename="evil.exe-blast-radius.csv"
 *
 * RFC 6266 does not say which duplicate a client must honour, so the downloaded
 * name becomes browser-dependent and attacker-influenced. Node rejects a CRLF in
 * a header value, so response splitting is already closed; this is about the
 * filename itself, which is what the person opening the file actually trusts.
 *
 * The allowlist is deliberately narrow rather than an escape of the quote
 * character: filenames also carry meaning to the filesystem, and a value that is
 * safe inside a header can still be unpleasant on disk.
 */
export function attachmentFilename(name: string): string {
  const safe = name.replaceAll(/[^a-zA-Z0-9_.-]/g, "_");
  return `attachment; filename="${safe}"`;
}

/**
 * The complete header set for a tenant-scoped download.
 *
 * Cache-Control belongs here rather than at each call site. Passing
 * `cache: "no-store"` to the upstream `fetch` governs whether Next.js reuses
 * that fetch; it says nothing about whether the response this route hands back
 * may be stored. Without an explicit policy these exports - one tenant's
 * credential findings, sessions, and blast radius - are cacheable by the browser
 * and by any shared cache on the path.
 *
 * Returning one object means a new export route gets the filename rule and the
 * cache rule together, which is the only reason the filename rule was missing
 * from one route to begin with.
 */
export function downloadHeaders(contentType: string, name: string): Record<string, string> {
  return {
    "Content-Type": contentType,
    "Content-Disposition": attachmentFilename(name),
    "Cache-Control": "no-store",
  };
}
