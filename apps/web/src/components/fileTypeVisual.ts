export type VisualKind = "image" | "video" | "audio" | "document" | "other";

const imageExtensions = new Set([
  "avif", "bmp", "dng", "gif", "heic", "heif", "jpeg", "jpg", "png", "svg", "tif", "tiff", "webp",
]);
const videoExtensions = new Set([
  "3g2", "3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "ts", "webm",
]);
const audioExtensions = new Set([
  "3ga", "aac", "amr", "flac", "m4a", "mid", "midi", "mp3", "oga", "ogg", "opus", "wav",
]);
const documentExtensions = new Set([
  "csv", "doc", "docx", "epub", "htm", "html", "json", "log", "md", "odp", "ods", "odt", "pdf", "ppt", "pptx", "rtf", "txt", "xls", "xlsx", "xml",
]);

export function fileVisualKind(category?: string | null, extension?: string | null): VisualKind {
  const normalizedCategory = (category ?? "").toLowerCase();
  if (["image", "video", "audio", "document"].includes(normalizedCategory)) {
    return normalizedCategory as VisualKind;
  }
  const normalizedExtension = (extension ?? "").replace(/^\./, "").toLowerCase();
  if (imageExtensions.has(normalizedExtension)) return "image";
  if (videoExtensions.has(normalizedExtension)) return "video";
  if (audioExtensions.has(normalizedExtension)) return "audio";
  if (documentExtensions.has(normalizedExtension)) return "document";
  return "other";
}
