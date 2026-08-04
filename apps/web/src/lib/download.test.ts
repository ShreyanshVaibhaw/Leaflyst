import { describe, expect, it } from "vitest";
import { attachmentFilename } from "./download";

describe("attachmentFilename", () => {
  it("keeps ordinary names intact", () => {
    expect(attachmentFilename("incident-sess-123.pdf")).toBe(
      'attachment; filename="incident-sess-123.pdf"',
    );
  });

  it("closes the quote break-out that injects a second filename", () => {
    // Interpolated raw, this produced:
    //   attachment; filename="session-x"; filename="evil.exe-blast-radius.csv"
    // and RFC 6266 leaves duplicate handling to the client.
    const header = attachmentFilename(`session-${'x"; filename="evil.exe'}-blast-radius.csv`);
    expect(header).toBe(
      'attachment; filename="session-x___filename__evil.exe-blast-radius.csv"',
    );
    expect(header.match(/filename=/g)).toHaveLength(1);
  });

  it("strips characters that would end the parameter or the header", () => {
    // ".." is deliberately absent: "." is kept so extensions survive, and a dot
    // pair cannot traverse anywhere once the path separators are gone.
    for (const hostile of ['"', ";", "\r", "\n", "/", "\\", "%00"]) {
      const header = attachmentFilename(`report-${hostile}.csv`);
      expect(header.match(/filename=/g)).toHaveLength(1);
      expect(header.slice('attachment; filename="'.length, -1)).not.toContain(hostile);
    }
  });

  it("does not let a session id add a Content-Disposition parameter", () => {
    expect(attachmentFilename("x; download=evil")).not.toContain("download=");
  });

  it("produces a header Node will actually accept", () => {
    // Node rejects CRLF in header values, so this asserts the sanitiser gets
    // there first rather than relying on the runtime to throw.
    const header = attachmentFilename("x\r\nSet-Cookie: evil=1");
    const response = new Response("body", { headers: { "Content-Disposition": header } });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("content-disposition")).toBe(header);
  });
});
