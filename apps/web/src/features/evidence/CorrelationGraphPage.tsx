import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  Download,
  GitFork,
  LoaderCircle,
  Search,
  ShieldAlert,
  Users,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  entityGraphExportUrl,
  getCase,
  getCorrelationGraph,
  getEntityGraph,
  type CorrelationNode,
  type CorrelationNodeType,
  type EntityGraphEdge,
  type EntityGraphNode,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";

interface Position {
  x: number;
  y: number;
}

export function CorrelationGraphPage() {
  const { caseId = "" } = useParams();
  const [viewMode, setViewMode] = useState<"identities" | "artifacts">("artifacts");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });

  const artifactGraphQuery = useQuery({
    queryKey: caseKeys.correlations(caseId),
    queryFn: () => getCorrelationGraph(caseId),
    enabled: Boolean(caseId) && viewMode === "artifacts",
  });

  const entityGraphQuery = useQuery({
    queryKey: caseKeys.entityGraph(caseId),
    queryFn: () => getEntityGraph(caseId),
    enabled: Boolean(caseId) && viewMode === "identities",
  });

  const artifactLayout = useMemo(
    () => positionArtifactNodes(artifactGraphQuery.data?.nodes ?? []),
    [artifactGraphQuery.data?.nodes],
  );

  const entityLayout = useMemo(
    () => positionEntityNodes(entityGraphQuery.data?.nodes ?? []),
    [entityGraphQuery.data?.nodes],
  );

  const selectedArtifact =
    artifactGraphQuery.data?.nodes.find((node) => node.id === selectedId) ?? null;
  const connectedArtifactEdges = selectedArtifact
    ? artifactGraphQuery.data?.edges.filter(
        (edge) => edge.source === selectedArtifact.id || edge.target === selectedArtifact.id,
      ) ?? []
    : [];

  const selectedEntity =
    entityGraphQuery.data?.nodes.find((node) => node.id === selectedId) ?? null;
  const connectedEntityEdges = selectedEntity
    ? entityGraphQuery.data?.edges.filter(
        (edge) => edge.source === selectedEntity.id || edge.target === selectedEntity.id,
      ) ?? []
    : [];

  const entityNodes = entityGraphQuery.data?.nodes;
  const filteredEntityNodes = useMemo(() => {
    if (!entityNodes) return [];
    if (!searchQuery.trim()) return entityNodes;
    const q = searchQuery.toLowerCase();
    return entityNodes.filter(
      (n) => n.label.toLowerCase().includes(q) || n.node_type.toLowerCase().includes(q),
    );
  }, [entityNodes, searchQuery]);

  return (
    <div className="mx-auto max-w-7xl">
      <CaseSubnav caseId={caseId} caseNumber={caseQuery.data?.case_number} />
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} /> Back to case
      </Link>

      <header className="mt-6 border-b border-white/8 pb-7">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="font-mono text-xs text-cyan-300/65">
              {caseQuery.data?.case_number ?? "Case link analysis"}
            </p>
            <h1 className="mt-2 text-3xl font-semibold text-white">
              {viewMode === "identities"
                ? "Cross-Source Entity Link Analysis"
                : "Investigation correlation graph"}
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
              {viewMode === "identities"
                ? "Correlates people, phones, emails, and communication links across normalized databases, Contacts, SMS, Call Logs, and carved fragments."
                : "Explainable links between devices, sealed sources, normalized artifacts, and explicit identifiers."}
            </p>
          </div>

          <div className="flex rounded-xl border border-white/10 bg-black/40 p-1">
            <button
              type="button"
              onClick={() => {
                setViewMode("identities");
                setSelectedId(null);
              }}
              className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
                viewMode === "identities"
                  ? "bg-cyan-500/20 text-cyan-200 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Users size={14} /> Identities & Comms
            </button>
            <button
              type="button"
              onClick={() => {
                setViewMode("artifacts");
                setSelectedId(null);
              }}
              className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
                viewMode === "artifacts"
                  ? "bg-cyan-500/20 text-cyan-200 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <GitFork size={14} /> Artifact Links
            </button>
          </div>
        </div>
      </header>

      {/* VIEW MODE: IDENTITIES & COMMUNICATIONS */}
      {viewMode === "identities" && (
        <>
          {entityGraphQuery.isPending && (
            <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
              <LoaderCircle size={16} className="animate-spin" /> Correlating identities & communication paths…
            </p>
          )}
          {entityGraphQuery.isError && (
            <div className="mt-6">
              <CaseError error={entityGraphQuery.error} />
            </div>
          )}
          {entityGraphQuery.data && (
            <>
              <div className="mt-6 grid gap-3 sm:grid-cols-4">
                <Metric label="Correlated Entities" value={entityGraphQuery.data.total_nodes} />
                <Metric label="Interaction Edges" value={entityGraphQuery.data.total_edges} />
                <Metric
                  label="Phone & Email Leads"
                  value={
                    entityGraphQuery.data.nodes.filter((n) => ["phone", "email"].includes(n.node_type))
                      .length
                  }
                />
                <Metric
                  label="Recovered / Carved Leads"
                  value={
                    entityGraphQuery.data.nodes.filter((n) => n.metadata.status === "recovered").length
                  }
                />
              </div>

              <div className="mt-4 flex flex-wrap items-center justify-between gap-4">
                <div className="flex flex-1 items-center gap-3">
                  <div className="relative max-w-xs flex-1">
                    <Search
                      size={14}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                    />
                    <input
                      type="text"
                      placeholder="Search entities or numbers…"
                      value={searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                      }}
                      className="w-full rounded-xl border border-white/10 bg-black/30 py-2 pl-9 pr-3 text-xs text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
                    />
                  </div>
                  <div className="flex items-center gap-1.5">
                    <a
                      href={entityGraphExportUrl(caseId, "graphml")}
                      download={`entity_graph_${caseId.slice(0, 8)}.graphml`}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-400/20 transition"
                      title="Download standard GraphML format for Gephi, Maltego, or i2 Analyst's Notebook"
                    >
                      <Download size={13} /> GraphML
                    </a>
                    <a
                      href={entityGraphExportUrl(caseId, "json")}
                      download={`entity_graph_${caseId.slice(0, 8)}.json`}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-white/10 transition"
                      title="Download raw JSON graph structure"
                    >
                      <Download size={13} /> JSON
                    </a>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-[11px] text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <span className="size-2.5 rounded-full bg-cyan-400" /> Person
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="size-2.5 rounded-full bg-amber-400" /> Phone
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="size-2.5 rounded-full bg-purple-400" /> Email
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="size-2.5 rounded-full bg-blue-400" /> Wi-Fi
                  </span>
                </div>
              </div>

              {entityGraphQuery.data.nodes.length === 0 ? (
                <div className="mt-7 rounded-2xl border border-white/8 bg-white/[0.025] p-8 text-sm text-slate-500">
                  No communication or contact records normalized yet. Run native parsers or carving on
                  your evidence twin sources to populate link analysis.
                </div>
              ) : (
                <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
                  <div className="overflow-auto rounded-2xl border border-white/8 bg-[#08131a] p-3">
                    <svg
                      viewBox={`0 0 960 ${String(entityLayout.height)}`}
                      className="min-h-[540px] min-w-[900px] w-full"
                      aria-label="Entity correlation graph"
                      role="img"
                    >
                      <defs>
                        <marker
                          id="arrowhead"
                          markerWidth="8"
                          markerHeight="6"
                          refX="20"
                          refY="3"
                          orient="auto"
                        >
                          <polygon points="0 0, 8 3, 0 6" fill="#0891b2" />
                        </marker>
                      </defs>

                      {/* Render Edges */}
                      <g stroke="#24404e" strokeWidth="1.5">
                        {entityGraphQuery.data.edges.map((edge, idx) => {
                          const srcPos = entityLayout.positions.get(edge.source);
                          const dstPos = entityLayout.positions.get(edge.target);
                          if (!srcPos || !dstPos) return null;
                          const isComms = edge.relation === "COMMUNICATED_WITH";
                          const isSelected =
                            selectedId === edge.source || selectedId === edge.target;
                          return (
                            <g key={`${edge.source}-${edge.target}-${edge.relation}-${String(idx)}`}>
                              <line
                                x1={srcPos.x}
                                y1={srcPos.y}
                                x2={dstPos.x}
                                y2={dstPos.y}
                                stroke={isSelected ? "#38bdf8" : isComms ? "#0891b2" : "#334155"}
                                strokeWidth={isSelected ? 2.5 : Math.min(3, 1 + edge.weight * 0.5)}
                                strokeDasharray={edge.relation.startsWith("HAS_") ? "3 3" : undefined}
                                markerEnd={isComms ? "url(#arrowhead)" : undefined}
                              />
                            </g>
                          );
                        })}
                      </g>

                      {/* Render Nodes */}
                      {entityGraphQuery.data.nodes.map((node) => {
                        const pos = entityLayout.positions.get(node.id);
                        if (!pos) return null;
                        const active = node.id === selectedId;
                        const isMatch =
                          searchQuery &&
                          filteredEntityNodes.some((filtered) => filtered.id === node.id);
                        const isRecovered = node.metadata.status === "recovered";

                        return (
                          <g
                            key={node.id}
                            role="button"
                            tabIndex={0}
                            aria-label={`${node.node_type}: ${node.label}`}
                            transform={`translate(${String(pos.x)}, ${String(pos.y)})`}
                            className="cursor-pointer outline-none transition"
                            onClick={() => {
                              setSelectedId(node.id);
                            }}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                setSelectedId(node.id);
                              }
                            }}
                          >
                            {isRecovered && (
                              <circle
                                r={27}
                                fill="none"
                                stroke="#f59e0b"
                                strokeWidth={2}
                                strokeDasharray="3 3"
                                className="animate-pulse"
                              />
                            )}
                            <circle
                              r={active ? 24 : 20}
                              fill={entityColor(node.node_type)}
                              stroke={active ? "#ffffff" : isMatch ? "#38bdf8" : "#24404e"}
                              strokeWidth={active || isMatch ? 3 : 1.5}
                            />
                            <text
                              y="35"
                              textAnchor="middle"
                              fill="#e2e8f0"
                              fontSize="11"
                              fontWeight={active ? "600" : "400"}
                              className="select-none"
                            >
                              {shortLabel(node.label)}
                            </text>
                            {node.count > 1 && (
                              <text
                                y="4"
                                textAnchor="middle"
                                fill="#ffffff"
                                fontSize="9"
                                fontWeight="700"
                                className="select-none pointer-events-none"
                              >
                                {node.count}
                              </text>
                            )}
                          </g>
                        );
                      })}
                    </svg>
                  </div>

                  <aside className="rounded-2xl border border-white/8 bg-white/[0.025] p-5">
                    {selectedEntity ? (
                      <EntityNodeDetails
                        node={selectedEntity}
                        connected={connectedEntityEdges}
                        caseId={caseId}
                      />
                    ) : (
                      <div>
                        <Users size={22} className="text-cyan-300" />
                        <h2 className="mt-4 text-lg font-semibold text-white">Select an entity</h2>
                        <p className="mt-2 text-xs leading-5 text-slate-500">
                          Select any person, phone number, email, or network node to view cross-source
                          correlations and forensic provenance.
                        </p>
                      </div>
                    )}
                  </aside>
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* VIEW MODE: ARTIFACT DEPENDENCY GRAPH */}
      {viewMode === "artifacts" && (
        <>
          {artifactGraphQuery.isPending && (
            <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
              <LoaderCircle size={16} className="animate-spin" /> Building artifact dependency graph…
            </p>
          )}
          {artifactGraphQuery.isError && (
            <div className="mt-6">
              <CaseError error={artifactGraphQuery.error} />
            </div>
          )}
          {artifactGraphQuery.data && (
            <>
              <div className="mt-6 grid gap-3 sm:grid-cols-4">
                <Metric label="Nodes" value={artifactGraphQuery.data.nodes.length} />
                <Metric label="Evidence links" value={artifactGraphQuery.data.edges.length} />
                <Metric
                  label="Explicit entities"
                  value={
                    artifactGraphQuery.data.nodes.filter(
                      (node) => !["device", "source", "artifact"].includes(node.node_type),
                    ).length
                  }
                />
                <Metric label="Builder" value={`v${artifactGraphQuery.data.builder_version}`} />
              </div>
              {artifactGraphQuery.data.nodes.length === 0 ? (
                <div className="mt-7 rounded-2xl border border-white/8 bg-white/[0.025] p-8 text-sm text-slate-500">
                  No normalized evidence is available yet. Acquire evidence or run compatible parsers,
                  then return to build the graph.
                </div>
              ) : (
                <div className="mt-7 grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
                  <div className="overflow-auto rounded-2xl border border-white/8 bg-[#08131a] p-3">
                    <svg
                      viewBox={`0 0 960 ${String(artifactLayout.height)}`}
                      className="min-h-[520px] min-w-[900px] w-full"
                      aria-label="Evidence correlation graph"
                      role="img"
                    >
                      <g stroke="#24404e" strokeWidth="1.25">
                        {artifactGraphQuery.data.edges.map((edge) => {
                          const source = artifactLayout.positions.get(edge.source);
                          const target = artifactLayout.positions.get(edge.target);
                          return source && target ? (
                            <line
                              key={edge.id}
                              x1={source.x}
                              y1={source.y}
                              x2={target.x}
                              y2={target.y}
                              strokeDasharray={edge.relation === "mentions" ? "4 4" : undefined}
                            />
                          ) : null;
                        })}
                      </g>
                      {artifactGraphQuery.data.nodes.map((node) => {
                        const position = artifactLayout.positions.get(node.id);
                        if (!position) return null;
                        const active = node.id === selectedId;
                        return (
                          <g
                            key={node.id}
                            role="button"
                            tabIndex={0}
                            aria-label={`${node.node_type}: ${node.label}`}
                            transform={`translate(${String(position.x)}, ${String(position.y)})`}
                            className="cursor-pointer outline-none"
                            onClick={() => {
                              setSelectedId(node.id);
                            }}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                setSelectedId(node.id);
                              }
                            }}
                          >
                            <circle
                              r={active ? 25 : 21}
                              fill={artifactNodeColor(node.node_type)}
                              stroke={active ? "#f8fafc" : "#3e6474"}
                              strokeWidth={active ? 3 : 1.5}
                            />
                            <text
                              y="38"
                              textAnchor="middle"
                              fill="#d9edf5"
                              fontSize="10"
                              className="select-none"
                            >
                              {shortLabel(node.label)}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                  <aside className="rounded-2xl border border-white/8 bg-white/[0.025] p-5">
                    {selectedArtifact ? (
                      <ArtifactNodeDetails
                        node={selectedArtifact}
                        caseId={caseId}
                        connected={connectedArtifactEdges.length}
                      />
                    ) : (
                      <div>
                        <GitFork size={22} className="text-cyan-300" />
                        <h2 className="mt-4 text-lg font-semibold text-white">Select a node</h2>
                        <p className="mt-2 text-xs leading-5 text-slate-500">
                          Choose any circle to inspect its type, confidence, and source-evidence link.
                        </p>
                      </div>
                    )}
                  </aside>
                </div>
              )}
              <div className="mt-5 rounded-xl border border-amber-300/15 bg-amber-300/5 p-4">
                <div className="flex gap-3">
                  <ShieldAlert size={18} className="mt-0.5 shrink-0 text-amber-200" />
                  <div>
                    {artifactGraphQuery.data.warnings.map((warning) => (
                      <p key={warning} className="text-xs leading-5 text-amber-100/75">
                        {warning}
                      </p>
                    ))}
                    <p className="mt-2 font-mono text-[10px] text-amber-100/45">
                      Graph SHA-256 {artifactGraphQuery.data.graph_hash}
                      {artifactGraphQuery.data.truncated
                        ? " · display truncated by safety limits"
                        : ""}
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

function EntityNodeDetails({
  node,
  connected,
  caseId,
}: {
  node: EntityGraphNode;
  connected: EntityGraphEdge[];
  caseId: string;
}) {
  const isRecovered = node.metadata.status === "recovered";
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="rounded-full border border-cyan-300/20 px-2 py-1 text-[10px] uppercase tracking-wider text-cyan-200">
          {node.node_type}
        </span>
        {isRecovered && (
          <span className="rounded-full bg-amber-500/20 px-2 py-1 text-[10px] font-semibold text-amber-300">
            Carved / Recovered
          </span>
        )}
      </div>
      <h2 className="mt-3 break-words text-lg font-semibold text-white">{node.label}</h2>
      <p className="mt-1 font-mono text-[11px] text-slate-500">{node.id}</p>

      {isRecovered && (
        <div className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/10 p-2.5 text-xs text-amber-200">
          Carved from SQLite unallocated freeblocks or freelist gap. Not visible in active application queries.
        </div>
      )}

      <dl className="mt-4 space-y-2 text-xs">
        <Detail label="Artifact Occurrences" value={String(node.count)} />
        <Detail label="Connected Relationships" value={String(connected.length)} />
      </dl>

      {connected.length > 0 && (
        <div className="mt-5 border-t border-white/8 pt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            Connected Links ({connected.length})
          </p>
          <div className="mt-2 max-h-60 space-y-2 overflow-y-auto pr-1">
            {connected.map((edge, i) => {
              const peer = edge.source === node.id ? edge.target : edge.source;
              const channels = edge.channels && edge.channels.length > 0 ? edge.channels.join(", ") : edge.channel;
              return (
                <div
                  key={i}
                  className="rounded-lg border border-white/5 bg-black/25 p-2 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11px] font-medium text-slate-300 truncate" title={peer}>
                      {shortLabel(peer)}
                    </span>
                    <span className="shrink-0 rounded bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 text-[10px] font-medium text-cyan-300">
                      {edge.relation}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] text-slate-400">
                    <span className="truncate">{channels}</span>
                    <span className="shrink-0 font-medium text-amber-200/80">
                      {edge.weight} {edge.weight === 1 ? "event" : "events"}
                    </span>
                  </div>
                  {edge.last_seen && (
                    <div className="mt-0.5 text-[9px] text-slate-500">
                      Latest: {edge.last_seen.replace("T", " ").slice(0, 19)}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="mt-5 border-t border-white/8 pt-4">
        <Link
          to={`/cases/${caseId}/evidence-twin`}
          className="inline-flex text-xs font-semibold text-cyan-200 hover:underline"
        >
          View in Evidence Twin sources →
        </Link>
      </div>
    </div>
  );
}

function ArtifactNodeDetails({
  node,
  caseId,
  connected,
}: {
  node: CorrelationNode;
  caseId: string;
  connected: number;
}) {
  return (
    <div>
      <span className="rounded-full border border-cyan-300/20 px-2 py-1 text-[10px] uppercase tracking-wider text-cyan-200">
        {node.node_type}
      </span>
      <h2 className="mt-4 break-words text-lg font-semibold text-white">{node.label}</h2>
      <p className="mt-2 text-xs text-slate-500">{node.subtitle ?? "Normalized evidence node"}</p>
      <dl className="mt-5 space-y-3 text-xs">
        <Detail label="Confidence" value={node.confidence} />
        <Detail label="Connected links" value={String(connected)} />
      </dl>
      {node.artifact_id && (
        <Link
          to={`/cases/${caseId}/evidence`}
          className="mt-5 inline-flex text-xs font-semibold text-cyan-200 hover:underline"
        >
          Open acquired artifact
        </Link>
      )}
      {node.source_artifact_id && (
        <Link
          to={`/cases/${caseId}/evidence-twin`}
          className="mt-5 inline-flex text-xs font-semibold text-cyan-200 hover:underline"
        >
          Open parsed source artifact
        </Link>
      )}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-slate-600">{label}</dt>
      <dd className="mt-1 text-slate-300">{value}</dd>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
      <p className="text-[10px] uppercase tracking-[0.15em] text-slate-600">{label}</p>
      <p className="mt-2 text-xl font-semibold text-white">{value}</p>
    </div>
  );
}

function positionEntityNodes(nodes: EntityGraphNode[]) {
  const columns: string[][] = [
    ["person"],
    ["phone", "email", "account"],
    ["wifi", "location", "system"],
  ];
  const positions = new Map<string, Position>();
  const xCoords = [140, 480, 820];
  let maximum = 0;

  columns.forEach((types, colIndex) => {
    const members = nodes.filter((node) => types.includes(node.node_type));
    maximum = Math.max(maximum, members.length);
    members.forEach((node, idx) => {
      positions.set(node.id, { x: xCoords[colIndex] ?? 480, y: 70 + idx * 75 });
    });
  });

  // Handle any other node types that didn't match the 3 columns
  const unplaced = nodes.filter((node) => !positions.has(node.id));
  unplaced.forEach((node, idx) => {
    positions.set(node.id, { x: 480, y: 70 + (maximum + idx) * 75 });
  });
  maximum += unplaced.length;

  return { positions, height: Math.max(540, 140 + maximum * 75) };
}

function positionArtifactNodes(nodes: CorrelationNode[]) {
  const columns: CorrelationNodeType[][] = [
    ["device", "source"],
    ["artifact"],
    [
      "identity",
      "phone",
      "email",
      "application",
      "conversation",
      "domain",
      "network",
      "location",
    ],
  ];
  const positions = new Map<string, Position>();
  const x = [110, 470, 830];
  let maximum = 0;
  columns.forEach((types, column) => {
    const members = nodes.filter((node) => types.includes(node.node_type));
    maximum = Math.max(maximum, members.length);
    members.forEach((node, index) => {
      positions.set(node.id, { x: x[column] ?? 470, y: 70 + index * 78 });
    });
  });
  return { positions, height: Math.max(520, 140 + maximum * 78) };
}

function entityColor(type: string): string {
  if (type === "person") return "#06b6d4";
  if (type === "phone") return "#f59e0b";
  if (type === "email") return "#a855f7";
  if (type === "account") return "#ec4899";
  if (type === "wifi") return "#3b82f6";
  return "#64748b";
}

function artifactNodeColor(type: CorrelationNodeType): string {
  if (type === "device") return "#0891b2";
  if (type === "source") return "#7c3aed";
  if (type === "artifact") return "#334155";
  if (type === "application") return "#be185d";
  if (type === "location" || type === "network") return "#047857";
  return "#a16207";
}

function shortLabel(value: string): string {
  return value.length > 22 ? `${value.slice(0, 20)}…` : value;
}
