import type { AcquisitionInventoryItem, AcquisitionScope } from "../../lib/api";

const IMAGE_EXTENSIONS = new Set([
  "avif", "bmp", "dng", "gif", "heic", "heif", "jpeg", "jpg", "png", "svg", "tif", "tiff", "webp",
]);
const VIDEO_EXTENSIONS = new Set([
  "3g2", "3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "ts", "webm",
]);
const AUDIO_EXTENSIONS = new Set([
  "3ga", "aac", "amr", "flac", "m4a", "mid", "midi", "mp3", "oga", "ogg", "opus", "wav",
]);
const MEDIA_EXTENSIONS = new Set([...IMAGE_EXTENSIONS, ...VIDEO_EXTENSIONS, ...AUDIO_EXTENSIONS]);

const DOCUMENT_EXTENSIONS = new Set([
  "csv", "doc", "docx", "epub", "htm", "html", "json", "log", "md", "odp", "ods",
  "odt", "pdf", "ppt", "pptx", "rtf", "txt", "xls", "xlsx", "xml",
]);

export type InventoryFilter = "all" | "images" | "videos" | "audio" | "media" | "documents" | "downloads";

export function matchesInventoryFilter(
  item: AcquisitionInventoryItem,
  filter: InventoryFilter,
): boolean {
  if (filter === "all") return true;
  const extension = (item.extension ?? "").toLowerCase();
  const path = item.relative_path.toLowerCase();
  if (filter === "images") return IMAGE_EXTENSIONS.has(extension);
  if (filter === "videos") return VIDEO_EXTENSIONS.has(extension);
  if (filter === "audio") return AUDIO_EXTENSIONS.has(extension);
  if (filter === "media") return MEDIA_EXTENSIONS.has(extension);
  if (filter === "documents") return DOCUMENT_EXTENSIONS.has(extension);
  return path.startsWith("download/") || path.startsWith("downloads/");
}

export function itemAllowedByScope(
  item: AcquisitionInventoryItem,
  scope: AcquisitionScope,
): boolean {
  if (scope === "image_files") return matchesInventoryFilter(item, "images");
  if (scope === "video_files") return matchesInventoryFilter(item, "videos");
  if (scope === "audio_files") return matchesInventoryFilter(item, "audio");
  if (scope === "media_files") return matchesInventoryFilter(item, "media");
  if (scope === "document_files") return matchesInventoryFilter(item, "documents");
  if (scope === "downloads_files") return matchesInventoryFilter(item, "downloads");
  return scope !== "metadata_only";
}
