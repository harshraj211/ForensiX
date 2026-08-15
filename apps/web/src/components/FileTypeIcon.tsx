import { FileAudio, FileQuestion, FileText, ImageIcon, Video } from "lucide-react";

import { fileVisualKind } from "./fileTypeVisual";

const visualCopy = {
  image: { Icon: ImageIcon, label: "Image", className: "border-cyan-200/20 bg-cyan-300/10 text-cyan-200" },
  video: { Icon: Video, label: "Video", className: "border-violet-200/20 bg-violet-300/10 text-violet-200" },
  audio: { Icon: FileAudio, label: "Audio", className: "border-amber-200/20 bg-amber-300/10 text-amber-200" },
  document: { Icon: FileText, label: "Document", className: "border-emerald-200/20 bg-emerald-300/10 text-emerald-200" },
  other: { Icon: FileQuestion, label: "File", className: "border-white/10 bg-white/5 text-slate-400" },
} as const;

export function FileTypeIcon({ category, extension, size = 50 }: {
  category?: string | null;
  extension?: string | null;
  size?: number;
}) {
  const kind = fileVisualKind(category, extension);
  const { Icon, label, className } = visualCopy[kind];
  return (
    <span
      role="img"
      aria-label={`${label} file`}
      title={`${label} file`}
      className={`grid shrink-0 place-items-center rounded-lg border ${className}`}
      style={{ width: size, height: size }}
    >
      <Icon size={Math.round(size * 0.46)} aria-hidden="true" />
    </span>
  );
}
