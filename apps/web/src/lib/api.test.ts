import { afterEach, describe, expect, it, vi } from "vitest";

import { rememberCsrfToken, runAcquisitionInventory } from "./api";

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function inventoryPage(items: object[], total: number, offset: number, limit: number) {
  return {
    id: "inventory-1",
    job_id: "job-1",
    case_id: "case-1",
    plan_id: "plan-1",
    device_id: "device-1",
    created_by: "user-1",
    root_id: "primary_alias",
    display_path: "/sdcard",
    status: "completed",
    discovered_count: total,
    persisted_count: total,
    skipped_count: 0,
    max_items: 5000,
    max_depth: 6,
    manifest_hash: "a".repeat(64),
    started_at: "2026-08-15T00:00:00Z",
    completed_at: "2026-08-15T00:01:00Z",
    items,
    total,
    offset,
    limit,
  };
}

function inventoryItem(ordinal: number, extension = "txt") {
  return {
    id: `item-${String(ordinal)}`,
    ordinal,
    relative_path: `Download/file-${String(ordinal)}.${extension}`,
    path_hash: "b".repeat(64),
    extension,
    size_bytes: 1,
    modified_time_raw: null,
    modified_at: null,
    timestamp_source: null,
    timestamp_confidence: null,
  };
}

afterEach(() => {
  rememberCsrfToken(null);
  vi.unstubAllGlobals();
});

describe("acquisition inventory paging", () => {
  it("reloads every sealed path after inventory and includes matches beyond page one", async () => {
    const firstPage = Array.from({ length: 500 }, (_, index) => inventoryItem(index + 1));
    const finalPhoto = inventoryItem(501, "jpg");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "/api/v1/cases/case-1/acquisitions/job-1/inventory" && init?.method === "POST") {
        return Promise.resolve(jsonResponse(inventoryPage(firstPage.slice(0, 100), 501, 0, 100)));
      }
      if (url.endsWith("/inventory?offset=0&limit=500")) {
        return Promise.resolve(jsonResponse(inventoryPage(firstPage, 501, 0, 500)));
      }
      if (url.endsWith("/inventory?offset=500&limit=500")) {
        return Promise.resolve(jsonResponse(inventoryPage([finalPhoto], 501, 500, 500)));
      }
      throw new Error(`Unhandled request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    rememberCsrfToken("csrf-test");

    const inventory = await runAcquisitionInventory("case-1", "job-1");

    expect(inventory.items).toHaveLength(501);
    expect(inventory.items.at(-1)?.relative_path).toBe("Download/file-501.jpg");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
