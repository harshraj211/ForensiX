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

  it("assesses an authorized device and labels unsupported access", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            detection_id: "detect-3",
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
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            assessment_id: "assessment-1",
            assessed_at: "2026-07-15T09:01:00Z",
            serial: "FX-DEMO-001",
            manufacturer: "ForensiX Labs",
            model: "Controlled Test Device",
            android_version: "14",
            sdk_level: 34,
            build_fingerprint: "forensix/demo",
            security_patch: "2026-07-01",
            package_count: 3,
            capabilities: {
              device_metadata: {
                status: "supported",
                reason_code: "ADB_PROPERTY_ACCESS",
                explanation: "Core properties were retrieved.",
              },
              private_app_data: {
                status: "unsupported",
                reason_code: "PRIVATE_APP_DATA_INACCESSIBLE",
                explanation: "ADB authorization does not grant private sandbox access.",
              },
            },
            warnings: ["Capability results can become stale."],
            assessor_version: "0.1.0",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderApp();

    await user.click(screen.getByRole("button", { name: "Detect Android devices" }));
    await user.click(await screen.findByRole("button", { name: "Assess capabilities" }));

    expect(await screen.findByText("Readiness snapshot")).toBeInTheDocument();
    expect(screen.getByText(/Android 14 · API 34 · 3 packages observed/)).toBeInTheDocument();
    expect(screen.getByText("Private App Data")).toBeInTheDocument();
    expect(screen.getByText("unsupported")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/devices/assess",
      expect.objectContaining({ body: JSON.stringify({ serial: "FX-DEMO-001" }) }),
    );
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
