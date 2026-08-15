import { describe, expect, it } from "vitest";

import type { AcquisitionInventoryItem } from "../../lib/api";
import { itemAllowedByScope, matchesInventoryFilter } from "./inventoryFileTypes";

function inventoryItem(relativePath: string, extension: string | null): AcquisitionInventoryItem {
  return {
    id: relativePath,
    ordinal: 1,
    relative_path: relativePath,
    path_hash: "hash",
    extension,
    size_bytes: 1,
    modified_time_raw: null,
    modified_at: null,
    timestamp_source: null,
    timestamp_confidence: null,
  };
}

describe("inventory file classification", () => {
  it.each([
    ["DCIM/Camera/photo.avif", "AVIF"],
    ["Movies/camera.3gp", "3gp"],
    ["Recordings/interview.opus", "opus"],
    ["Pictures/scan.tiff", "tiff"],
  ])("recognizes media %s", (relativePath, extension) => {
    expect(matchesInventoryFilter(inventoryItem(relativePath, extension), "media")).toBe(true);
  });

  it.each([
    ["Documents/export.json", "json"],
    ["Download/page.html", "html"],
    ["Books/manual.epub", "epub"],
    ["Documents/device.xml", "XML"],
  ])("recognizes document %s", (relativePath, extension) => {
    expect(matchesInventoryFilter(inventoryItem(relativePath, extension), "documents")).toBe(true);
  });

  it("matches download folders case-insensitively", () => {
    expect(matchesInventoryFilter(inventoryItem("Download/export.bin", "bin"), "downloads")).toBe(true);
    expect(matchesInventoryFilter(inventoryItem("DOWNLOADS/export.bin", "bin"), "downloads")).toBe(true);
  });

  it("keeps the scope guard aligned with visible filters", () => {
    const media = inventoryItem("Movies/clip.3gp", "3gp");
    expect(itemAllowedByScope(media, "media_files")).toBe(true);
    expect(itemAllowedByScope(media, "document_files")).toBe(false);
  });

  it("keeps photos, videos, and audio in separate scopes", () => {
    const photo = inventoryItem("DCIM/photo.jpg", "jpg");
    const video = inventoryItem("Movies/clip.mp4", "mp4");
    const audio = inventoryItem("Recordings/interview.opus", "opus");
    expect(itemAllowedByScope(photo, "image_files")).toBe(true);
    expect(itemAllowedByScope(photo, "video_files")).toBe(false);
    expect(itemAllowedByScope(video, "video_files")).toBe(true);
    expect(itemAllowedByScope(video, "audio_files")).toBe(false);
    expect(itemAllowedByScope(audio, "audio_files")).toBe(true);
    expect(itemAllowedByScope(audio, "image_files")).toBe(false);
  });
});
