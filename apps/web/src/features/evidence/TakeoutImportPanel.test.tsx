import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { type CloudExportImport, importCloudExport } from "../../lib/api";
import { CloudExportResult, TakeoutImportPanel } from "./TakeoutImportPanel";

vi.mock("../../lib/api", () => ({ importCloudExport: vi.fn() }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

const result = {
  evidence_source: { sha256: "original-hash" },
  parser_run: { status: "completed", run_hash: "run-hash" },
  summary: { parsed_count: 2, member_count: 4, undated_count: 1, source_timezone: "Asia/Kolkata", date_order: "DMY", unsupported_count: 1, malformed_count: 0, record_counts: { whatsapp_export_message: 2 }, warnings: ["msgstore.crypt15: unsupported"] },
} as unknown as CloudExportImport;

describe("cloud export imports", () => {
  it("selects a provider, sends examiner timezone/date order and displays import results", async () => {
    vi.mocked(importCloudExport).mockResolvedValue(result);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><TakeoutImportPanel caseId="case-one" /></QueryClientProvider>);
    const user = userEvent.setup();
    expect(screen.getByRole("button", { name: "Import Google export" })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Cloud export provider"), "whatsapp");
    await user.clear(screen.getByLabelText("Source timezone"));
    await user.type(screen.getByLabelText("Source timezone"), "Asia/Kolkata");
    await user.selectOptions(screen.getByLabelText("WhatsApp date order"), "MDY");
    const file = new File(["chat export"], "chat.txt", { type: "text/plain" });
    await user.upload(screen.getByLabelText("Cloud export file"), file);
    await user.click(screen.getByRole("button", { name: "Import WhatsApp export" }));
    await waitFor(() => { expect(importCloudExport).toHaveBeenCalledWith("case-one", file, "whatsapp", "Asia/Kolkata", "MDY"); });
    expect(await screen.findByText("Export sealed and parsed")).toBeInTheDocument();
    expect(screen.getByText(/2 parsed records/)).toBeInTheDocument();
    await user.click(screen.getByText("Import issues (1)"));
    expect(screen.getByText("msgstore.crypt15: unsupported")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Cloud export provider"), "telegram");
    expect(screen.queryByText("Export sealed and parsed")).not.toBeInTheDocument();
    expect(screen.getByText(/Telegram Desktop JSON/)).toBeInTheDocument();
  });

  it("distinguishes a sealed original from a failed parser", () => {
    if (!result.parser_run) throw new Error("Fixture parser run missing");
    render(<CloudExportResult result={{ ...result, parser_run: { ...result.parser_run, status: "failed", error_message: "Archive path traversal rejected" }, summary: {} }} />);
    expect(screen.getByText("Original sealed; parsing failed")).toBeInTheDocument();
    expect(screen.getByText("Archive path traversal rejected")).toBeInTheDocument();
    expect(screen.queryByText("Export sealed and parsed")).not.toBeInTheDocument();
  });

  it("disables intake controls when the case is closed or archived", () => {
    const client = new QueryClient();
    render(<QueryClientProvider client={client}><TakeoutImportPanel caseId="closed-case" writable={false} /></QueryClientProvider>);
    expect(screen.getByLabelText("Cloud export provider")).toBeDisabled();
    expect(screen.getByLabelText("Cloud export file")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Import Google export" })).toBeDisabled();
    expect(screen.getByText("Cloud export imports are unavailable in this case state.")).toBeInTheDocument();
  });
});
