import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { EscapedPayload } from "./escaped-payload";

describe("EscapedPayload", () => {
  it("renders stored prompt injection as inert text", () => {
    const payload = '<script>globalThis.pwned=true</script><img src=x onerror="alert(1)">';
    const html = renderToStaticMarkup(<EscapedPayload value={payload} />);

    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img");
  });
});
