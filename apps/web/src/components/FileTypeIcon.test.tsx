import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FileTypeIcon } from "./FileTypeIcon";
import { fileVisualKind } from "./fileTypeVisual";

describe("FileTypeIcon", () => {
  it.each([
    ["jpg", "image"],
    ["MP4", "video"],
    ["pdf", "document"],
    ["opus", "audio"],
    ["bin", "other"],
  ] as const)("classifies .%s as %s", (extension, kind) => {
    expect(fileVisualKind(null, extension)).toBe(kind);
  });

  it("renders a compact accessible image tile", () => {
    render(<FileTypeIcon category="image" extension="bin" />);
    expect(screen.getByRole("img", { name: "Image file" })).toHaveStyle({
      width: "50px",
      height: "50px",
    });
  });
});
