interface NativeDownloadStart {
  status: "ready" | "cancelled";
  download_id?: string;
}

interface NativeDownloadApi {
  start_download(filename: string): Promise<NativeDownloadStart>;
  append_download(downloadId: string, chunkBase64: string): Promise<unknown>;
  finish_download(downloadId: string): Promise<unknown>;
  cancel_download(downloadId: string): Promise<unknown>;
}

declare global {
  interface Window {
    pywebview?: { api?: Partial<NativeDownloadApi> };
  }
}

const CHUNK_SIZE = 512 * 1024;

export async function downloadFile(url: string, filename = "forensix-download") {
  const native = window.pywebview?.api;
  if (isNativeDownloadApi(native)) {
    await downloadInNativeWindow(native, url, filename);
    return;
  }

  // The regular browser owns its download manager. Keeping this as an anchor
  // avoids buffering large evidence files in the browser process.
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noreferrer";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

async function downloadInNativeWindow(api: NativeDownloadApi, url: string, filename: string) {
  const started = await api.start_download(filename);
  if (started.status === "cancelled") return;
  const downloadId = started.download_id;
  if (!downloadId) throw new Error("The native download session was not created.");

  try {
    const response = await fetch(url, { credentials: "same-origin" });
    if (!response.ok) {
      throw new Error(`The local service returned HTTP ${String(response.status)}.`);
    }
    const body = response.body;
    if (body === null) throw new Error("The local service returned an unreadable download stream.");
    for await (const chunk of body) {
      if (chunk.byteLength > 0) {
        await appendBytes(api, downloadId, chunk);
      }
    }
    await api.finish_download(downloadId);
  } catch (error) {
    await api.cancel_download(downloadId).catch(() => undefined);
    throw error;
  }
}

async function appendBytes(api: NativeDownloadApi, downloadId: string, bytes: Uint8Array) {
  for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
    const chunk = bytes.subarray(offset, offset + CHUNK_SIZE);
    let binary = "";
    for (let chunkOffset = 0; chunkOffset < chunk.length; chunkOffset += 0x8000) {
      binary += String.fromCharCode(...chunk.subarray(chunkOffset, chunkOffset + 0x8000));
    }
    await api.append_download(downloadId, btoa(binary));
  }
}

function isNativeDownloadApi(api: Partial<NativeDownloadApi> | undefined): api is NativeDownloadApi {
  return Boolean(
    api?.start_download &&
      api.append_download &&
      api.finish_download &&
      api.cancel_download,
  );
}
