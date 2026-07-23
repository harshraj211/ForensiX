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

function renderApp(initialEntry = "/devices", authUser = AUTH_USER) {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false, staleTime: Infinity },
    },
  });
  queryClient.setQueryData(["auth", "bootstrap"], { bootstrap_required: false });
  queryClient.setQueryData(["auth", "me"], authUser);
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

  it("creates a custody checkpoint and records an external anchor receipt", async () => {
    const now = "2026-07-20T01:00:00Z";
    let created = false;
    let recordedAnchor = false;
    let verifiedSignature = false;
    const checkpoint = {
      id: "checkpoint-1",
      case_id: "case-1",
      created_by: "user-1",
      custody_record_count: 1,
      custody_head_hash: "a".repeat(64),
      audit_sequence: 7,
      audit_head_hash: "b".repeat(64),
      filename: "ForensiX_FX-2026-CHECK001_CustodyCheckpoint.json",
      size_bytes: 2048,
      sha256: "c".repeat(64),
      schema_version: "1.0.0",
      anchor_status: "not_externally_anchored",
      created_at: now,
    };
    const anchor = {
      id: "anchor-1",
      checkpoint_id: checkpoint.id,
      case_id: checkpoint.case_id,
      recorded_by: "user-1",
      anchor_type: "evidence_vault",
      anchor_provider: "ForensiX Validation Vault",
      anchor_reference: "VAULT-2026-001",
      anchored_at: now,
      checkpoint_sha256: checkpoint.sha256,
      receipt_sha256: null,
      notes: "Controlled validation receipt",
      anchor_hash: "d".repeat(64),
      created_at: now,
    };
    const signature = {
      id: "signature-1",
      checkpoint_id: checkpoint.id,
      case_id: checkpoint.case_id,
      verified_by: "user-1",
      signature_algorithm: "rsa_pkcs1v15_sha256",
      signer_subject: "CN=ForensiX Controlled Signer",
      signer_issuer: "CN=ForensiX Controlled CA",
      certificate_serial: "1234abcd",
      certificate_sha256: "e".repeat(64),
      signature_sha256: "f".repeat(64),
      signed_at: now,
      certificate_not_before: "2026-07-19T01:00:00Z",
      certificate_not_after: "2027-07-20T01:00:00Z",
      checkpoint_sha256: checkpoint.sha256,
      verification_hash: "1".repeat(64),
      created_at: now,
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(jsonResponse({
          id: "case-1",
          case_number: "FX-2026-CHECK001",
          title: "Custody checkpoint case",
          description: null,
          legal_authority: "Controlled validation",
          status: "active",
          created_by: "user-1",
          created_at: now,
          updated_at: now,
          closed_at: null,
          version: 1,
        }));
      }
      if (url === "/api/v1/cases/case-1/devices") {
        return Promise.resolve(jsonResponse([]));
      }
      if (url === "/api/v1/cases/case-1/custody") {
        return Promise.resolve(jsonResponse([]));
      }
      if (url === "/api/v1/cases/case-1/custody/verify") {
        return Promise.resolve(jsonResponse({
          valid: true,
          record_count: 0,
          broken_sequence: null,
          head_hash: null,
        }));
      }
      if (url === "/api/v1/cases/case-1/custody/checkpoints") {
        if (init?.method === "POST") {
          created = true;
          return Promise.resolve(jsonResponse(checkpoint, 201));
        }
        return Promise.resolve(jsonResponse(created ? [checkpoint] : []));
      }
      if (
        url ===
        "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/anchors"
      ) {
        if (init?.method === "POST") {
          recordedAnchor = true;
          return Promise.resolve(jsonResponse(anchor, 201));
        }
        return Promise.resolve(jsonResponse(recordedAnchor ? [anchor] : []));
      }
      if (
        url ===
        "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/signatures"
      ) {
        return Promise.resolve(jsonResponse(verifiedSignature ? [signature] : []));
      }
      if (
        url ===
        "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/signatures/verify"
      ) {
        verifiedSignature = true;
        return Promise.resolve(jsonResponse(signature, 201));
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderApp("/cases/case-1", {
      ...AUTH_USER,
      permissions: ["custody:review", "audit:view"],
    });

    expect(await screen.findByText("External checkpoint package")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create sealed checkpoint" }));

    expect(await screen.findByText("not externally anchored")).toBeInTheDocument();
    expect(screen.getByText(/audit #7/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download JSON" })).toHaveAttribute(
      "href",
      "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/download",
    );

    await user.selectOptions(screen.getByLabelText("Anchor type"), "evidence_vault");
    await user.type(screen.getByLabelText("Provider"), anchor.anchor_provider);
    await user.type(screen.getByLabelText("Reference"), anchor.anchor_reference);
    await user.type(screen.getByLabelText("Notes"), anchor.notes);
    await user.click(screen.getByRole("button", { name: "Record external anchor" }));

    expect(
      await screen.findByText(
        `${anchor.anchor_provider} - ${anchor.anchor_reference}`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(`Anchor SHA-256 ${anchor.anchor_hash}`)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/anchors",
      expect.objectContaining({ method: "POST" }),
    );

    await user.upload(
      screen.getByLabelText("Public certificate (PEM)"),
      new File(["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"], "signer.pem"),
    );
    await user.upload(
      screen.getByLabelText("Detached signature"),
      new File([new Uint8Array([1, 2, 3, 4])], "checkpoint.sig"),
    );
    await user.click(screen.getByRole("button", { name: "Verify signature" }));

    expect(
      await screen.findByText(`Signature verified - ${signature.signer_subject}`),
    ).toBeInTheDocument();
    expect(
      screen.getByText(`Verification SHA-256 ${signature.verification_hash}`),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/custody/checkpoints/checkpoint-1/signatures/verify",
      expect.objectContaining({ method: "POST" }),
    );
  }, 10_000);
});

describe("audit review", () => {
  it("shows the verified hash chain and Evidence Twin audit detail", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/api/v1/audit-logs?limit=500") {
        return Promise.resolve(
          jsonResponse([
            {
              id: "audit-1",
              sequence: 1,
              case_id: "case-1",
              actor_id: "user-1",
              event_type: "evidence_parser_completed",
              object_type: "evidence_parser_run",
              object_id: "run-1",
              detail: { parser_id: "android.telephony.sms", artifact_count: 1 },
              previous_hash: "0".repeat(64),
              entry_hash: "a".repeat(64),
              created_at: "2026-07-19T10:00:00Z",
            },
          ]),
        );
      }
      if (url === "/api/v1/audit-logs/verify") {
        return Promise.resolve(
          jsonResponse({
            valid: true,
            record_count: 1,
            broken_sequence: null,
            head_hash: "a".repeat(64),
          }),
        );
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp("/audit");

    expect(await screen.findByRole("heading", { name: "Audit log" })).toBeInTheDocument();
    expect(await screen.findByText("1 records verified")).toBeInTheDocument();
    expect(screen.getByText("evidence parser completed")).toBeInTheDocument();
    expect(screen.getByText(/android.telephony.sms/)).toBeInTheDocument();
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
      if (url === "/api/v1/cases/case-1/devices/device-1/root-probes") {
        return Promise.resolve(
          jsonResponse(
            {
              id: "probe-0000-0000-0000-000000000001",
              case_id: "case-1",
              device_id: "device-1",
              probed_by: "user-1",
              status: "available",
              uid: 0,
              identity: "uid=0(root) gid=0(root)",
              reason_code: "ROOT_UID_CONFIRMED",
              potential_side_effect: "Root manager activity may be created.",
              probe_hash: "a".repeat(64),
              expires_at: new Date(Date.now() + 300_000).toISOString(),
              probed_at: new Date().toISOString(),
            },
            201,
          ),
        );
      }
      if (url === "/api/v1/integrations/physical-acquisition") {
        return Promise.resolve(
          jsonResponse({
            enabled: true,
            max_size_bytes: 1048576,
            maturity: "experimental",
            warning: "Experimental raw userdata acquisition does not bypass encryption.",
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/devices/device-1/physical-block-probes") {
        return Promise.resolve(
          jsonResponse(
            {
              id: "physical-probe-0000-0000-0000000001",
              case_id: "case-1",
              device_id: "device-1",
              root_probe_id: "probe-0000-0000-0000-000000000001",
              probed_by: "user-1",
              profile: "userdata_by_name",
              device_path: "/dev/block/by-name/userdata",
              size_bytes: 8192,
              encryption_state: "unknown",
              probe_hash: "e".repeat(64),
              probed_at: new Date().toISOString(),
            },
            201,
          ),
        );
      }
      if (url === "/api/v1/cases/case-1/devices/device-1/physical-captures") {
        return Promise.resolve(
          jsonResponse(
            {
              id: "physical-source-1",
              case_id: "case-1",
              device_id: "device-1",
              created_by: "user-1",
              source_type: "physical_block",
              acquisition_level: "physical",
              status: "sealed",
              display_name: "Experimental userdata block image",
              source_name: "userdata.dd",
              container_format: "dd",
              size_bytes: 8192,
              sha256: "f".repeat(64),
              chunks_sha256: "1".repeat(64),
              manifest_sha256: "2".repeat(64),
              chunk_size_bytes: 4194304,
              chunk_count: 1,
              read_only_applied: true,
              validation_state: "experimental_unvalidated",
              limitations: ["The image may remain encrypted and is not resumable."],
              tool_version: "0.1.0",
              error_code: null,
              error_message: null,
              sealed_at: new Date().toISOString(),
              created_at: new Date().toISOString(),
            },
            201,
          ),
        );
      }
      if (url === "/api/v1/cases/case-1/devices/device-1/rooted-captures") {
        return Promise.resolve(
          jsonResponse(
            {
              id: "source-1",
              case_id: "case-1",
              device_id: "device-1",
              created_by: "user-1",
              source_type: "rooted_filesystem",
              acquisition_level: "filesystem",
              status: "sealed",
              display_name: "Rooted Android provider bundle",
              source_name: "android_providers.tar",
              container_format: "tar",
              size_bytes: 10240,
              sha256: "b".repeat(64),
              chunks_sha256: "c".repeat(64),
              manifest_sha256: "d".repeat(64),
              chunk_size_bytes: 4194304,
              chunk_count: 1,
              read_only_applied: true,
              validation_state: "sealed_unverified_acquisition",
              limitations: ["This is not a physical or bit-for-bit device image."],
              tool_version: "0.1.0",
              error_code: null,
              error_message: null,
              sealed_at: new Date().toISOString(),
              created_at: new Date().toISOString(),
            },
            201,
          ),
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
    await user.click(screen.getByLabelText(/authorize this elevated-access probe/i));
    await user.click(screen.getByRole("button", { name: "Probe rooted access" }));
    expect(await screen.findByText("Root access available")).toBeInTheDocument();
    await user.click(screen.getByLabelText(/authorize this bounded rooted collection/i));
    await user.click(screen.getByRole("button", { name: "Capture provider bundle" }));
    expect(await screen.findByText("Evidence Twin source sealed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Evidence Twin workspace" })).toHaveAttribute(
      "href",
      "/cases/case-1/evidence-twin",
    );
    await user.click(screen.getByLabelText(/authorize the fixed system-artifact allowlist/i));
    await user.click(screen.getByRole("button", { name: "Capture system-artifact bundle" }));
    expect(await screen.findByText("System-artifact Evidence Twin source sealed")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/devices/device-1/rooted-captures",
      expect.objectContaining({
        body: JSON.stringify({
          serial: "FX-DEMO-001",
          root_probe_id: "probe-0000-0000-0000-000000000001",
          profile: "android_system",
          side_effects_acknowledged: true,
        }),
      }),
    );
    await user.click(screen.getByLabelText(/authorize the fixed private-application allowlist/i));
    await user.click(screen.getByRole("button", { name: "Capture private-app bundle" }));
    expect(
      await screen.findByText("Private-application Evidence Twin source sealed"),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/devices/device-1/rooted-captures",
      expect.objectContaining({
        body: JSON.stringify({
          serial: "FX-DEMO-001",
          root_probe_id: "probe-0000-0000-0000-000000000001",
          profile: "android_apps",
          side_effects_acknowledged: true,
        }),
      }),
    );
    await user.click(screen.getByLabelText(/authorize a metadata-only probe/i));
    await user.click(screen.getByRole("button", { name: "Probe userdata block" }));
    expect(await screen.findByText("Fixed block located")).toBeInTheDocument();
    await user.click(screen.getByLabelText(/authorize the full raw stream/i));
    await user.click(screen.getByLabelText(/resulting image may remain encrypted/i));
    await user.click(screen.getByLabelText(/cannot currently resume/i));
    await user.click(screen.getByRole("button", { name: "Acquire experimental raw image" }));
    expect(await screen.findByText("Physical Evidence Twin source sealed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open physical source in Evidence Twin" })).toHaveAttribute(
      "href",
      "/cases/case-1/evidence-twin",
    );
  });
});

describe("acquisition planning", () => {
  it("creates a frozen plan without starting acquisition", async () => {
    let created = false;
    let jobState: "ready" | "completed" | null = null;
    let fileAcquired = false;
    let verificationComplete = false;
    const assessedAt = new Date().toISOString();
    const plan = {
      id: "plan-1",
      case_id: "case-1",
      device_id: "device-1",
      assessment_id: "assessment-1",
      created_by: "user-1",
      scope: "quick_triage",
      status: "ready",
      modules: ["device_metadata", "package_inventory", "shared_storage_inventory"],
      limitations: ["Controlled Logical Triage Mode is not hardware write blocking."],
      snapshot_hash: "a".repeat(64),
      plan_hash: "b".repeat(64),
      schema_version: "1.0.0",
      readiness_assessed_at: assessedAt,
      readiness_expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      created_at: assessedAt,
    };
    const acquisitionJob = () => ({
      id: "job-1",
      case_id: "case-1",
      plan_id: "plan-1",
      owner_id: "user-1",
      state: jobState,
      progress_percent: jobState === "completed" ? 100 : 5,
      current_step:
        jobState === "completed"
          ? "Bounded path inventory persisted with manifest hash"
          : "Immutable plan validated; awaiting bounded executor",
      current_module: jobState === "completed" ? "shared_storage_inventory" : null,
      cancellation_requested: false,
      resume_supported: true,
      checkpoint: { phase: "prepared", plan_id: "plan-1", plan_hash: plan.plan_hash },
      error_code: null,
      error_message: null,
      result_reference: jobState === "completed" ? "inventory-1" : null,
      last_event_sequence: jobState === "completed" ? 11 : 4,
      version: jobState === "completed" ? 11 : 4,
      created_at: assessedAt,
      updated_at: assessedAt,
      started_at: null,
      completed_at: jobState === "completed" ? assessedAt : null,
      executor_available: false,
    });
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(
          jsonResponse({
            id: "case-1",
            case_number: "FX-2026-PLAN0001",
            title: "Planning case",
            description: null,
            legal_authority: "Controlled validation",
            status: "open",
            created_by: "user-1",
            created_at: assessedAt,
            updated_at: assessedAt,
            closed_at: null,
            version: 1,
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/devices") {
        return Promise.resolve(
          jsonResponse([
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
              first_seen_at: assessedAt,
              last_seen_at: assessedAt,
            },
          ]),
        );
      }
      if (url === "/api/v1/cases/case-1/devices/device-1/assessments") {
        return Promise.resolve(
          jsonResponse([
            {
              id: "assessment-1",
              case_id: "case-1",
              device_id: "device-1",
              assessed_by: "user-1",
              assessed_at: assessedAt,
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
                device_metadata: { status: "supported" },
                package_inventory: { status: "supported" },
                shared_storage: { status: "supported" },
              },
              warnings: [],
              assessor_version: "0.2.0",
            },
          ]),
        );
      }
      if (url === "/api/v1/cases/case-1/acquisition-plans?offset=0&limit=50") {
        return Promise.resolve(
          jsonResponse({ items: created ? [plan] : [], total: created ? 1 : 0, offset: 0, limit: 50 }),
        );
      }
      if (url === "/api/v1/cases/case-1/acquisition-plans" && init?.method === "POST") {
        created = true;
        return Promise.resolve(jsonResponse(plan, 201));
      }
      if (url === "/api/v1/cases/case-1/acquisitions?offset=0&limit=50") {
        return Promise.resolve(
          jsonResponse({
            items: jobState ? [acquisitionJob()] : [],
            total: jobState ? 1 : 0,
            offset: 0,
            limit: 50,
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/acquisitions" && init?.method === "POST") {
        jobState = "ready";
        return Promise.resolve(jsonResponse(acquisitionJob(), 201));
      }
      if (url === "/api/v1/cases/case-1/acquisitions/job-1/inventory" && init?.method === "POST") {
        jobState = "completed";
        return Promise.resolve(
          jsonResponse({
            id: "inventory-1",
            job_id: "job-1",
            case_id: "case-1",
            plan_id: "plan-1",
            device_id: "device-1",
            created_by: "user-1",
            root_id: "primary_alias",
            display_path: "/sdcard",
            status: "completed",
            discovered_count: 3,
            persisted_count: 3,
            skipped_count: 0,
            max_items: 250,
            max_depth: 6,
            manifest_hash: "c".repeat(64),
            started_at: assessedAt,
            completed_at: assessedAt,
            items: [
              {
                id: "item-1",
                ordinal: 1,
                relative_path: "DCIM/Camera/IMG_0001.jpg",
                path_hash: "d".repeat(64),
                extension: "jpg",
                size_bytes: 31,
                modified_time_raw: null,
                modified_at: null,
                timestamp_source: null,
                timestamp_confidence: null,
              },
              {
                id: "item-2",
                ordinal: 2,
                relative_path: "Documents/timeline.csv",
                path_hash: "c".repeat(64),
                extension: "csv",
                size_bytes: 40,
                modified_time_raw: null,
                modified_at: null,
                timestamp_source: null,
                timestamp_confidence: null,
              },
              {
                id: "item-3",
                ordinal: 3,
                relative_path: "Download/notes.txt",
                path_hash: "b".repeat(64),
                extension: "txt",
                size_bytes: 12,
                modified_time_raw: null,
                modified_at: null,
                timestamp_source: null,
                timestamp_confidence: null,
              },
            ],
            total: 3,
            offset: 0,
            limit: 100,
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/acquisitions/job-1/files") {
        return Promise.resolve(
          jsonResponse(
            fileAcquired
              ? [
                  {
                    id: "file-1",
                    inventory_id: "inventory-1",
                    inventory_item_id: "item-1",
                    job_id: "job-1",
                    case_id: "case-1",
                    plan_id: "plan-1",
                    device_id: "device-1",
                    acquired_by: "user-1",
                    status: "completed",
                    source_root_id: "primary_alias",
                    source_path_hash: "d".repeat(64),
                    storage_key: "c/case-1/r/file-1.jpg",
                    manifest_storage_key: "c/case-1/m/file-1.json",
                    size_bytes: 31,
                    sha256: "e".repeat(64),
                    manifest_hash: "f".repeat(64),
                    transfer_limit_bytes: 104857600,
                    tool_version: "0.1.0",
                    validation_state: "not_physically_validated",
                    partial_preserved: false,
                    error_code: null,
                    error_message: null,
                    started_at: assessedAt,
                    completed_at: assessedAt,
                  },
                  {
                    id: "file-2",
                    inventory_id: "inventory-1",
                    inventory_item_id: "item-2",
                    job_id: "job-1",
                    case_id: "case-1",
                    plan_id: "plan-1",
                    device_id: "device-1",
                    acquired_by: "user-1",
                    status: "completed",
                    source_root_id: "primary_alias",
                    source_path_hash: "c".repeat(64),
                    storage_key: "c/case-1/r/file-2.csv",
                    manifest_storage_key: "c/case-1/m/file-2.json",
                    size_bytes: 40,
                    sha256: "1".repeat(64),
                    manifest_hash: "2".repeat(64),
                    transfer_limit_bytes: 104857600,
                    tool_version: "0.1.0",
                    validation_state: "not_physically_validated",
                    partial_preserved: false,
                    error_code: null,
                    error_message: null,
                    started_at: assessedAt,
                    completed_at: assessedAt,
                  },
                  {
                    id: "file-3",
                    inventory_id: "inventory-1",
                    inventory_item_id: "item-3",
                    job_id: "job-1",
                    case_id: "case-1",
                    plan_id: "plan-1",
                    device_id: "device-1",
                    acquired_by: "user-1",
                    status: "completed",
                    source_root_id: "primary_alias",
                    source_path_hash: "b".repeat(64),
                    storage_key: "c/case-1/r/file-3.txt",
                    manifest_storage_key: "c/case-1/m/file-3.json",
                    size_bytes: 12,
                    sha256: "3".repeat(64),
                    manifest_hash: "4".repeat(64),
                    transfer_limit_bytes: 104857600,
                    tool_version: "0.1.0",
                    validation_state: "not_physically_validated",
                    partial_preserved: false,
                    error_code: null,
                    error_message: null,
                    started_at: assessedAt,
                    completed_at: assessedAt,
                  },
                ]
              : [],
          ),
        );
      }
      if (url === "/api/v1/cases/case-1/acquisitions/job-1/partials") {
        return Promise.resolve(jsonResponse([]));
      }
      if (url === "/api/v1/cases/case-1/acquisitions/job-1/verifications") {
        return Promise.resolve(
          jsonResponse(
            verificationComplete
              ? [
                  {
                    id: "verification-1",
                    evidence_file_id: "file-1",
                    case_id: "case-1",
                    job_id: "job-1",
                    verified_by: "user-1",
                    status: "verified",
                    expected_file_sha256: "e".repeat(64),
                    observed_file_sha256: "e".repeat(64),
                    file_size_bytes: 31,
                    file_matches: true,
                    expected_manifest_sha256: "f".repeat(64),
                    observed_manifest_sha256: "f".repeat(64),
                    manifest_matches: true,
                    error_code: null,
                    verification_hash: "a".repeat(64),
                    tool_version: "0.1.0",
                    verified_at: assessedAt,
                  },
                ]
              : [],
          ),
        );
      }
      if (
        url === "/api/v1/cases/case-1/acquisitions/job-1/inventory/acquire-batch" &&
        init?.method === "POST"
      ) {
        fileAcquired = true;
        return Promise.resolve(
          jsonResponse({
            batch_id: "batch-1",
            case_id: "case-1",
            job_id: "job-1",
            requested_count: 3,
            completed_count: 3,
            failed_count: 0,
            skipped_count: 0,
            items: [
              {
                inventory_item_id: "item-1",
                outcome: "completed",
                file: {
                  id: "file-1",
                  inventory_id: "inventory-1",
                  inventory_item_id: "item-1",
                  job_id: "job-1",
                  case_id: "case-1",
                  plan_id: "plan-1",
                  device_id: "device-1",
                  acquired_by: "user-1",
                  status: "completed",
                  source_root_id: "primary_alias",
                  source_path_hash: "d".repeat(64),
                  storage_key: "c/case-1/r/file-1.jpg",
                  manifest_storage_key: "c/case-1/m/file-1.json",
                  size_bytes: 31,
                  sha256: "e".repeat(64),
                  manifest_hash: "f".repeat(64),
                  transfer_limit_bytes: 104857600,
                  tool_version: "0.1.0",
                  validation_state: "not_physically_validated",
                  partial_preserved: false,
                  error_code: null,
                  error_message: null,
                  started_at: assessedAt,
                  completed_at: assessedAt,
                },
                error_code: null,
                error_message: null,
              },
            ],
          }),
        );
      }
      if (
        url === "/api/v1/cases/case-1/acquisitions/job-1/inventory/items/item-1/acquire" &&
        init?.method === "POST"
      ) {
        fileAcquired = true;
        return Promise.resolve(
          jsonResponse({
            id: "file-1",
            inventory_id: "inventory-1",
            inventory_item_id: "item-1",
            job_id: "job-1",
            case_id: "case-1",
            plan_id: "plan-1",
            device_id: "device-1",
            acquired_by: "user-1",
            status: "completed",
            source_root_id: "primary_alias",
            source_path_hash: "d".repeat(64),
            storage_key: "c/case-1/r/file-1.jpg",
            manifest_storage_key: "c/case-1/m/file-1.json",
            size_bytes: 31,
            sha256: "e".repeat(64),
            manifest_hash: "f".repeat(64),
            transfer_limit_bytes: 104857600,
            tool_version: "0.1.0",
            validation_state: "not_physically_validated",
            partial_preserved: false,
            error_code: null,
            error_message: null,
            started_at: assessedAt,
            completed_at: assessedAt,
          }),
        );
      }
      if (
        url === "/api/v1/cases/case-1/acquisitions/job-1/files/file-1/verify" &&
        init?.method === "POST"
      ) {
        verificationComplete = true;
        return Promise.resolve(
          jsonResponse({
            id: "verification-1",
            evidence_file_id: "file-1",
            case_id: "case-1",
            job_id: "job-1",
            verified_by: "user-1",
            status: "verified",
            expected_file_sha256: "e".repeat(64),
            observed_file_sha256: "e".repeat(64),
            file_size_bytes: 31,
            file_matches: true,
            expected_manifest_sha256: "f".repeat(64),
            observed_manifest_sha256: "f".repeat(64),
            manifest_matches: true,
            error_code: null,
            verification_hash: "a".repeat(64),
            tool_version: "0.1.0",
            verified_at: assessedAt,
          }),
        );
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderApp("/cases/case-1/acquisitions");

    expect(await screen.findByRole("heading", { name: "Acquisition planning" })).toBeInTheDocument();
    expect(await screen.findByText("The latest readiness snapshot supports this scope.")).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: /I acknowledge/i }));
    await user.click(screen.getByRole("button", { name: "Create frozen plan" }));

    expect(await screen.findByText("Plan created without starting acquisition.")).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Quick triage", level: 3 }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Prepare durable job" }));

    expect(await screen.findByText("Durable job")).toBeInTheDocument();
    expect(await screen.findByText(/4 durable events \/ not running/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run bounded path inventory" }));
    expect(await screen.findByText("3 path records · completed")).toBeInTheDocument();
    expect(screen.getByText("DCIM/Camera/IMG_0001.jpg")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select all visible" }));
    await user.click(screen.getByRole("button", { name: "Acquire selected (3)" }));
    expect(await screen.findByText(/Batch batch-1… finished: 3 completed/i)).toBeInTheDocument();
    expect(await screen.findByText("31 bytes acquired")).toBeInTheDocument();
    expect(screen.getByText(`SHA-256 ${"e".repeat(64)}`)).toBeInTheDocument();
    const verifyButtons = screen.getAllByRole("button", { name: "Verify integrity" });
    expect(verifyButtons.length).toBeGreaterThan(0);
    const verifyButton = verifyButtons.at(0);
    if (!verifyButton) throw new Error("Expected an integrity verification button.");
    await user.click(verifyButton);
    expect(await screen.findByText("Integrity verified")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/acquisitions/job-1/inventory/acquire-batch",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ item_ids: ["item-1", "item-2", "item-3"] }),
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/acquisition-plans",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          device_id: "device-1",
          assessment_id: "assessment-1",
          scope: "quick_triage",
          limitations_acknowledged: true,
        }),
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/cases/case-1/acquisitions",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ plan_id: "plan-1" }),
      }),
    );
  });
});

describe("Evidence Twin workspace", () => {
  it("shows sealed source integrity and working-copy controls", async () => {
    const now = "2026-07-19T12:00:00Z";
    const source = {
      id: "source-1",
      case_id: "case-1",
      device_id: null,
      created_by: "user-1",
      source_type: "imported_file",
      acquisition_level: "filesystem",
      status: "sealed",
      display_name: "Controlled Android image",
      source_name: "capture.raw",
      container_format: "raw",
      size_bytes: 4096,
      sha256: "a".repeat(64),
      chunks_sha256: "b".repeat(64),
      manifest_sha256: "c".repeat(64),
      chunk_size_bytes: 4 * 1024 * 1024,
      chunk_count: 1,
      read_only_applied: true,
      validation_state: "sealed_unverified_import",
      limitations: ["Imported evidence is not claimed to have been acquired by ForensiX."],
      tool_version: "0.1.0",
      error_code: null,
      error_message: null,
      sealed_at: now,
      created_at: now,
    };
    const workingCopy = {
      id: "copy-1",
      evidence_source_id: source.id,
      case_id: source.case_id,
      created_by: "user-1",
      status: "ready",
      size_bytes: source.size_bytes,
      expected_source_sha256: source.sha256,
      observed_sha256: source.sha256,
      copy_method: "stream_copy",
      verified_at: now,
      created_at: now,
    };
    const inspection = {
      id: "inspection-1",
      evidence_source_id: source.id,
      working_copy_id: workingCopy.id,
      case_id: source.case_id,
      inspected_by: "user-1",
      detected_type: "sqlite",
      confidence: "high",
      encryption_state: "not_detected",
      signature: { magic: "SQLite format 3" },
      warnings: ["SQLite examination uses read-only immutable connections."],
      detector_version: "1.0.0",
      inspection_hash: "d".repeat(64),
      inspected_at: now,
    };
    const recoveryAssessment = {
      id: "recovery-1",
      evidence_source_id: source.id,
      working_copy_id: workingCopy.id,
      inspection_id: inspection.id,
      case_id: source.case_id,
      assessed_by: "user-1",
      maturity: "experimental",
      status: "candidate_regions_observed",
      candidate_region_count: 3,
      candidates: [
        {
          source_locator: "working_copy",
          source_kind: "sqlite_database",
          status: "candidate_regions_observed",
          confidence: "medium",
          page_size_bytes: 4096,
          candidate_region_count: 3,
          source_size_bytes: 4096,
          metadata: { freelist_page_count_header: 3 },
          limitations: ["Freelist pages do not prove deleted records exist."],
          candidate_hash: "e".repeat(64),
        },
      ],
      limitations: ["Candidate regions are not recovered records or proof of deletion."],
      assessment_hash: "f".repeat(64),
      tool_version: "1.0.0",
      assessed_at: now,
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(jsonResponse({
          id: "case-1",
          case_number: "FX-2026-TWIN0001",
          title: "Evidence Twin case",
          description: null,
          legal_authority: "Controlled validation",
          status: "active",
          created_by: "user-1",
          created_at: now,
          updated_at: now,
          closed_at: null,
          version: 1,
        }));
      }
      if (url === "/api/v1/cases/case-1/evidence-sources") {
        return Promise.resolve(jsonResponse([source]));
      }
      if (url === "/api/v1/integrations/aleapp") {
        return Promise.resolve(jsonResponse({
          available: false,
          hash_verified: false,
          release_label: "not_configured",
          program_path: "",
          observed_sha256: null,
          message: "ALEAPP is optional and not configured.",
        }));
      }
      if (url === "/api/v1/integrations/application-artifacts") {
        return Promise.resolve(jsonResponse([
          {
            app_id: "whatsapp",
            display_name: "WhatsApp",
            status: "plaintext_parser",
            maturity: "experimental",
            native_parser_id: "android.whatsapp.message",
            acquisition_requirements: ["A lawfully acquired plaintext database is required."],
            limitations: ["Non-rooted ADB cannot normally read the private database."],
          },
          {
            app_id: "signal",
            display_name: "Signal",
            status: "detection_only",
            maturity: "experimental",
            native_parser_id: null,
            acquisition_requirements: ["A lawfully acquired database is required."],
            limitations: ["Signal databases are commonly SQLCipher-encrypted."],
          },
        ]));
      }
      if (url.endsWith("/working-copies")) return Promise.resolve(jsonResponse([workingCopy]));
      if (url.endsWith("/inspection")) return Promise.resolve(jsonResponse(inspection));
      if (url.endsWith("/recovery-assessment")) {
        return Promise.resolve(jsonResponse(recoveryAssessment));
      }
      if (url.endsWith("/verifications")) return Promise.resolve(jsonResponse([]));
      if (url.endsWith("/parser-runs")) return Promise.resolve(jsonResponse([]));
      if (url.endsWith("/artifacts")) return Promise.resolve(jsonResponse([]));
      if (url.endsWith("/tool-outputs")) return Promise.resolve(jsonResponse([]));
      return Promise.reject(new Error(`Unexpected request: ${url}`));
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp("/cases/case-1/evidence-twin");

    expect(await screen.findByRole("heading", { name: "Evidence Twin" })).toBeInTheDocument();
    expect(screen.getByLabelText("Evidence image or extraction")).toHaveAttribute(
      "accept",
      expect.stringContaining(".raw"),
    );
    expect(await screen.findByRole("heading", { name: "Controlled Android image" })).toBeInTheDocument();
    expect(screen.getByText(`Master SHA-256`)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify sealed master" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Create verified working copy" })).toBeEnabled();
    expect(await screen.findByText(/Detected/)).toHaveTextContent("sqlite");
    expect(screen.getByRole("button", { name: "Run compatible Android parsers" })).toBeEnabled();
    const recoveryButton = screen.getByRole("button", {
      name: "Assess recovery candidates (experimental)",
    });
    expect(recoveryButton).toBeEnabled();
    await userEvent.click(recoveryButton);
    expect(
      await screen.findByText("Candidate regions are not recovered records"),
    ).toBeInTheDocument();
    expect(screen.getByText(/observed 3 candidate region/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run pinned ALEAPP" })).toBeDisabled();
    expect(screen.getByText(/ALEAPP is optional and not configured/i)).toBeInTheDocument();
    expect(await screen.findByText("WhatsApp")).toBeInTheDocument();
    expect(screen.getByText("No native content parser")).toBeInTheDocument();
    expect(screen.getByText(/do not decrypt Signal/i)).toBeInTheDocument();
    expect(screen.getByText(/not claimed to have been acquired by ForensiX/i)).toBeInTheDocument();
  });
});

describe("evidence explorer", () => {
  it("searches normalized metadata and shows provenance without rendering content", async () => {
    const collectedAt = "2026-07-16T10:00:00Z";
    const artifact = {
      id: "artifact-1",
      evidence_file_id: "file-1",
      case_id: "case-1",
      device_id: "device-1",
      job_id: "job-1",
      category: "document",
      subtype: "file",
      title: "timeline.csv",
      summary: "Document file acquired from approved shared storage.",
      source_relative_path: "Documents/timeline.csv",
      source_path_hash: "d".repeat(64),
      extension: "csv",
      detected_mime: "text/csv",
      size_bytes: 43,
      status: "active",
      primary_sha256: "e".repeat(64),
      parser_id: "generic_file_metadata",
      parser_version: "1.0.0",
      timestamp_confidence: "high",
      collected_at: collectedAt,
      provenance: { evidence_file_id: "file-1", device_id: "device-1" },
      metadata: {
        content_parsed: false,
        classification_basis: "filename_extension_only",
        limitations: [
          "Media type was mapped from the filename extension and was not content-sniffed.",
        ],
      },
      schema_version: "1.0.0",
      created_at: collectedAt,
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(
          jsonResponse({
            id: "case-1",
            case_number: "FX-2026-EVIDENCE",
            title: "Evidence search case",
            description: null,
            legal_authority: null,
            status: "active",
            created_by: "user-1",
            created_at: collectedAt,
            updated_at: collectedAt,
            closed_at: null,
            version: 1,
          }),
        );
      }
      if (url.startsWith("/api/v1/cases/case-1/artifacts?")) {
        return Promise.resolve(
          jsonResponse({
            items: [artifact],
            total: 1,
            offset: 0,
            limit: 100,
            category_facets: { document: 1 },
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/artifacts/artifact-1") {
        return Promise.resolve(jsonResponse(artifact));
      }
      if (url === "/api/v1/cases/case-1/artifacts/artifact-1/annotations") {
        return Promise.resolve(jsonResponse({ bookmark: null, tags: [], notes: [] }));
      }
      if (url === "/api/v1/cases/case-1/artifacts/artifact-1/preview") {
        return Promise.resolve(jsonResponse({
          id: null,
          artifact_id: "artifact-1",
          status: "not_generated",
          detected_mime: null,
          extension_mismatch: false,
          output_mime: null,
          output_size_bytes: null,
          output_sha256: null,
          width: null,
          height: null,
          worker_version: null,
          limits: {},
          error_code: null,
          error_message: null,
          created_at: null,
        }));
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp("/cases/case-1/evidence");

    expect(await screen.findByRole("heading", { name: "Evidence explorer" })).toBeInTheDocument();
    expect(await screen.findByText("1 evidence folders")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Documents/i }));
    expect((await screen.findAllByText("timeline.csv")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("Documents/timeline.csv")).length).toBeGreaterThan(0);
    expect(await screen.findByText("Extension-derived MIME")).toBeInTheDocument();
    expect(screen.getByText("text/csv")).toBeInTheDocument();
    expect(screen.getByText(/Downloads are independently SHA-256 verified/i)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /View file/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Download original/i })).toHaveAttribute(
      "href",
      "/api/v1/cases/case-1/artifacts/artifact-1/content",
    );
    expect(screen.getByText(`SHA-256`)).toBeInTheDocument();
  });

  it("shows explicit collection-time claims in the chronological timeline", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/api/v1/cases/case-1") {
        return Promise.resolve(
          jsonResponse({
            id: "case-1",
            case_number: "FX-2026-TIMELINE",
            title: "Timeline case",
            description: null,
            legal_authority: null,
            status: "active",
            created_by: "user-1",
            created_at: "2026-07-16T10:00:00Z",
            updated_at: "2026-07-16T10:00:00Z",
            closed_at: null,
            version: 1,
          }),
        );
      }
      if (url === "/api/v1/cases/case-1/timeline?offset=0&limit=200") {
        return Promise.resolve(
          jsonResponse({
            items: [
              {
                id: "event-1",
                case_id: "case-1",
                artifact_id: "artifact-1",
                job_id: "job-1",
                category: "file",
                timestamp_type: "acquisition_collected_at",
                event_time: "2026-07-16T10:00:00Z",
                original_time: "2026-07-16T10:00:00+00:00",
                timezone_basis: "UTC recorded by acquisition workstation",
                precision: "microsecond",
                confidence: "high",
                summary: "ForensiX collected timeline.csv.",
                builder_version: "1.0.0",
                event_hash: "a".repeat(64),
              },
            ],
            total: 1,
            offset: 0,
            limit: 200,
            category_facets: { file: 1 },
          }),
        );
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp("/cases/case-1/timeline");

    expect(await screen.findByRole("heading", { name: "Timeline" })).toBeInTheDocument();
    expect(await screen.findByText("ForensiX collected timeline.csv.")).toBeInTheDocument();
    expect(screen.getByText(/acquisition collected at/i)).toBeInTheDocument();
    expect(screen.getByText("UTC recorded by acquisition workstation")).toBeInTheDocument();
    expect(screen.getByText(/No missing device-side timestamps are inferred/i)).toBeInTheDocument();
  });
});
