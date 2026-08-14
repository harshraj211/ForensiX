import type { AcquisitionInventoryItem, AcquisitionScope } from "../../lib/api";

const MEDIA_EXTENSIONS = new Set([
  "3g2", "3ga", "3gp", "aac", "amr", "avif", "avi", "bmp", "dng", "flac", "gif",
  "heic", "heif", "jpeg", "jpg", "m4a", "m4v", "mid", "midi", "mkv", "mov", "mp3",
  "mp4", "mpeg", "mpg", "oga", "ogg", "opus", "png", "svg", "tif", "tiff", "ts",
  "wav", "webm", "webp",
]);

const DOCUMENT_EXTENSIONS = new Set([
  "csv", "doc", "docx", "epub", "htm", "html", "json", "log", "md", "odp", "ods",
  "odt", "pdf", "ppt", "pptx", "rtf", "txt", "xls", "xlsx", "xml",
]);

export type InventoryFilter = "all" | "media" | "documents" | "downloads";

export function matchesInventoryFilter(
  item: AcquisitionInventoryItem,
  filter: InventoryFilter,
): boolean {
  if (filter === "all") return true;
  const extension = (item.extension ?? "").toLowerCase();
  const path = item.relative_path.toLowerCase();
  if (filter === "media") return MEDIA_EXTENSIONS.has(extension);
  if (filter === "documents") return DOCUMENT_EXTENSIONS.has(extension);
  return path.startsWith("download/") || path.startsWith("downloads/");
}

export function itemAllowedByScope(
  item: AcquisitionInventoryItem,
  scope: AcquisitionScope,
): boolean {
  if (scope === "media_files") return matchesInventoryFilter(item, "media");
  if (scope === "document_files") return matchesInventoryFilter(item, "documents");
  if (scope === "downloads_files") return matchesInventoryFilter(item, "downloads");
  return scope !== "metadata_only";
}
