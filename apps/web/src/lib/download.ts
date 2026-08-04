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
