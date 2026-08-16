import { useState, type MouseEvent, type ReactNode } from "react";

import { downloadFile } from "../lib/downloads";

interface DownloadLinkProps {
  href: string;
  filename?: string;
  className?: string;
  children: ReactNode;
}

export function DownloadLink({ href, filename, className, children }: DownloadLinkProps) {
  const [error, setError] = useState<string | null>(null);

  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    event.preventDefault();
    setError(null);
    void downloadFile(href, filename).catch((reason: unknown) => {
      setError(reason instanceof Error ? reason.message : "The download could not be saved.");
    });
  };

  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-2">
      <a
        href={href}
        download={filename}
        onClick={handleClick}
        aria-busy={error === null ? undefined : "false"}
        className={className}
      >
        {children}
      </a>
      {error && <span role="alert" className="text-[10px] text-rose-300">Download failed: {error}</span>}
    </span>
  );
}
