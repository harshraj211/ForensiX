import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { rememberCsrfToken } from "./lib/api";

const AUTH_USER = {
  user_id: "user-1",
  username: "admin.user",
  display_name: "Test Administrator",
  roles: ["administrator"],
  permissions: ["devices:operate"],
};

function renderApp(initialEntry = "/devices") {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false, staleTime: Infinity },
    },
  });
  queryClient.setQueryData(["auth", "bootstrap"], { bootstrap_required: false });
  queryClient.setQueryData(["auth", "me"], AUTH_USER);
  rememberCsrfToken("csrf-test");
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function renderFreshApp() {
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

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  rememberCsrfToken(null);
  vi.unstubAllGlobals();
});

describe("local authentication", () => {
  it("shows one-time administrator bootstrap on a fresh workstation", async () => {
    mockResponse({ bootstrap_required: true });

    renderFreshApp();

    expect(
      await screen.findByRole("heading", { name: "Create the first administrator" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Confirm password")).toHaveAttribute(
      "autocomplete",
      "new-password",
    );
  });

  it("shows login when bootstrap is complete and no session exists", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ bootstrap_required: false }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: {
              code: "AUTHENTICATION_REQUIRED",
              message: "A valid local ForensiX session is required.",
              details: {},
              request_id: "auth-1",
            },
          }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    renderFreshApp();

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toHaveAttribute(
      "autocomplete",
      "current-password",
    );
  });
});

describe("case workspace", () => {
  it("lists accessible cases with lifecycle state", async () => {
    mockResponse({
      items: [
        {
          id: "case-1",
          case_number: "FX-2026-ABC12345",
          title: "Controlled Android examination",
          description: "Known validation device",
          legal_authority: "Internal authorization",
          status: "open",
          created_by: "user-1",
          created_at: "2026-07-15T10:00:00Z",
          updated_at: "2026-07-15T10:00:00Z",
          closed_at: null,
          version: 1,
        },
      ],
      total: 1,
      offset: 0,
      limit: 50,
    });

    renderApp("/cases");

    expect(await screen.findByRole("heading", { name: "Cases" })).toBeInTheDocument();
    expect(await screen.findByText("Controlled Android examination")).toBeInTheDocument();
    expect(screen.getByText("FX-2026-ABC12345")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
  });

  it("opens the case creation form", async () => {
    mockResponse({ items: [], total: 0, offset: 0, limit: 50 });
    const user = userEvent.setup();
    renderApp("/cases");

    await user.click(await screen.findByRole("button", { name: "New case" }));

    expect(screen.getByRole("heading", { name: "Create case" })).toBeInTheDocument();
    expect(screen.getByLabelText("Case title")).toBeRequired();
    expect(screen.getByLabelText("Legal authority")).toBeInTheDocument();
  });
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
            storage_roots: [
              {
                root_id: "primary_alias",
                display_path: "/sdcard",
                status: "accessible",
                exists: true,
                readable: true,
                reason_code: "ROOT_READABLE",
              },
            ],
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
    expect(screen.getByText("Content-free root probe")).toBeInTheDocument();
    expect(screen.getByText("/sdcard")).toBeInTheDocument();
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

  it("persists readiness inside the selected case and refreshes its device registry", async () => {
    let assessed = false;
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(
          jsonResponse({
            id: "case-1",
            case_number: "FX-2026-CASE0001",
            title: "Scoped readiness case",
            description: null,
            legal_authority: "Controlled validation",
            status: "open",
            created_by: "user-1",
            created_at: "2026-07-15T09:00:00Z",
            updated_at: "2026-07-15T09:00:00Z",
            closed_at: null,
            version: 1,
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/devices") {
        return Promise.resolve(
          jsonResponse(
            assessed
              ? [
                  {
                    id: "device-1",
                    case_id: "case-1",
                    serial_suffix: "O-001",
                    manufacturer: "ForensiX Labs",
                    model: "Controlled Test Device",
                    android_version: "14",
                    sdk_level: 34,
                    build_fingerprint: "forensix/demo",
                    security_patch: "2026-07-01",
                    registered_by: "user-1",
                    first_seen_at: "2026-07-15T09:01:00Z",
                    last_seen_at: "2026-07-15T09:01:00Z",
                  },
                ]
              : [],
          ),
        );
      }
      if (url === "/api/v1/devices/detect?case_id=case-1") {
        return Promise.resolve(
          jsonResponse({
            detection_id: "detect-case-1",
            case_id: "case-1",
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
        );
      }
      if (url === "/api/v1/devices/assess") {
        assessed = true;
        return Promise.resolve(
          jsonResponse({
            assessment_id: "assessment-case-1",
            case_id: "case-1",
            case_device_id: "device-1",
            assessed_at: "2026-07-15T09:01:00Z",
            serial: "FX-DEMO-001",
            manufacturer: "ForensiX Labs",
            model: "Controlled Test Device",
            android_version: "14",
            sdk_level: 34,
            build_fingerprint: "forensix/demo",
            security_patch: "2026-07-01",
            package_count: 3,
            storage_roots: [
              {
                root_id: "primary_alias",
                display_path: "/sdcard",
                status: "accessible",
                exists: true,
                readable: true,
                reason_code: "ROOT_READABLE",
              },
            ],
            capabilities: {
              device_metadata: {
                status: "supported",
                reason_code: "ADB_PROPERTY_ACCESS",
                explanation: "Core properties were retrieved.",
              },
            },
            warnings: ["Capability results can become stale."],
            assessor_version: "0.1.0",
          }),
        );
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderApp("/cases/case-1/devices");

    expect(await screen.findByText("FX-2026-CASE0001")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Detect Android devices" }));
    await user.click(await screen.findByRole("button", { name: "Assess capabilities" }));

    expect(await screen.findByText(/Snapshot saved to this case's device history/i)).toBeInTheDocument();
    expect(await screen.findByText("1 linked")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/devices/assess",
      expect.objectContaining({
        body: JSON.stringify({ serial: "FX-DEMO-001", case_id: "case-1" }),
      }),
    );
  });
});
