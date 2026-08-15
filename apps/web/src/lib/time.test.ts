import { describe, expect, it } from "vitest";

import { formatUtcAsLocal, utcDate } from "./time";

describe("UTC timestamp handling", () => {
  it("treats offset-less API timestamps as UTC", () => {
    expect(utcDate("2026-08-15T12:30:00").toISOString()).toBe("2026-08-15T12:30:00.000Z");
  });

  it("preserves timestamps that already include an offset", () => {
    expect(utcDate("2026-08-15T18:00:00+05:30").toISOString()).toBe(
      "2026-08-15T12:30:00.000Z",
    );
  });

  it("does not display an invalid date as a misleading time", () => {
    expect(formatUtcAsLocal("not-a-date")).toBe("Invalid timestamp");
  });
});
