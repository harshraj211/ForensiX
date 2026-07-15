import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function renderApp() {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/devices"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockResponse(body: unknown, status = 200, requestId = "req-test") {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
      }),
    ),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("device readiness", () => {
  it("states the controlled triage limitation before detection", () => {
    renderApp();

    expect(screen.getByRole("heading", { name: "Device readiness" })).toBeInTheDocument();
    expect(screen.getByText(/ADB is not a hardware write blocker/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Detect Android devices" })).toBeEnabled();
  });

  it("renders an authorized device returned by the local API", async () => {
    mockResponse({
      detection_id: "detect-1",
      observed_at: "2026-07-15T09:00:00Z",
      result: "single_device",
      adb: { version: "1.0.41", executable_path: "mock://adb" },
      devices: [
        {
          serial: "FX-DEMO-001",
          state: "authorized",
          raw_state: "device",
          product: "forensix_demo",
          model: "Controlled_Test_Device",
          device: "fx_virtual",
          transport_id: "1",
          usb: "1-1",
        },
      ],
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(screen.getByRole("button", { name: "Detect Android devices" }));

    expect(await screen.findByText("Authorized")).toBeInTheDocument();
    expect(screen.getByText("Controlled Test Device")).toBeInTheDocument();
    expect(screen.getByText("Serial ending O-001")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/devices/detect",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows actionable authorization guidance", async () => {
    mockResponse({
      detection_id: "detect-2",
      observed_at: "2026-07-15T09:00:00Z",
      result: "single_device",
      adb: { version: "1.0.41", executable_path: "mock://adb" },
      devices: [
        {
          serial: "FX-DEMO-001",
          state: "unauthorized",
          raw_state: "unauthorized",
          product: null,
          model: null,
          device: null,
          transport_id: "1",
          usb: "1-1",
        },
      ],
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(screen.getByRole("button", { name: "Detect Android devices" }));

    expect(await screen.findByText("Authorization required")).toBeInTheDocument();
    expect(screen.getByText(/approve this workstation on the Android device/i)).toBeInTheDocument();
  });

  it("shows the safe API error and request ID", async () => {
    mockResponse(
      {
        error: {
          code: "ADB_NOT_FOUND",
          message: "Android Platform Tools ADB was not found.",
          details: {},
          request_id: "req-missing-adb",
        },
      },
      503,
      "req-missing-adb",
    );
    const user = userEvent.setup();
    renderApp();

    await user.click(screen.getByRole("button", { name: "Detect Android devices" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("ADB was not found");
    expect(screen.getByText("Request req-missing-adb")).toBeInTheDocument();
  });
});
