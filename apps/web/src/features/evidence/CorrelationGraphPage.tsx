import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, GitFork, LoaderCircle, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  getCase,
  getCorrelationGraph,
  type CorrelationNode,
  type CorrelationNodeType,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

interface Position {
  x: number;
  y: number;
}

export function CorrelationGraphPage() {
  const { caseId = "" } = useParams();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const graphQuery = useQuery({
    queryKey: caseKeys.correlations(caseId),
    queryFn: () => getCorrelationGraph(caseId),
    enabled: Boolean(caseId),
  });
  const layout = useMemo(
    () => positionNodes(graphQuery.data?.nodes ?? []),
    [graphQuery.data?.nodes],
  );
  const selected = graphQuery.data?.nodes.find((node) => node.id === selectedId) ?? null;
  const connected = selected
    ? graphQuery.data?.edges.filter(
        (edge) => edge.source === selected.id || edge.target === selected.id,
      ) ?? []
    : [];

  return (
    <div className="mx-auto max-w-7xl">
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">
          {caseQuery.data?.case_number ?? "Case correlations"}
        </p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Investigation correlation graph</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
          Explainable links between devices, sealed sources, normalized artifacts, and explicit
          identifiers. Shared values are investigative leads—not proof that two people or accounts
          are the same.
        </p>
      </header>
      {(graphQuery.isPending || caseQuery.isPending) && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Building evidence graph…
        </p>
      )}
      {graphQuery.isError && <div className="mt-6"><CaseError error={graphQuery.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}
      {graphQuery.data && (
        <>
          <div className="mt-6 grid gap-3 sm:grid-cols-4">
            <Metric label="Nodes" value={graphQuery.data.nodes.length} />
            <Metric label="Evidence links" value={graphQuery.data.edges.length} />
            <Metric
              label="Explicit entities"
              value={graphQuery.data.nodes.filter((node) => !["device", "source", "artifact"].includes(node.node_type)).length}
            />
            <Metric label="Builder" value={`v${graphQuery.data.builder_version}`} />
          </div>
          {graphQuery.data.nodes.length === 0 ? (
            <div className="mt-7 rounded-2xl border border-white/8 bg-white/[0.025] p-8 text-sm text-slate-500">
              No normalized evidence is available yet. Acquire evidence or run compatible parsers,
              then return to build the graph.
            </div>
          ) : (
            <div className="mt-7 grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
              <div className="overflow-auto rounded-2xl border border-white/8 bg-[#08131a] p-3">
                <svg
                  viewBox={`0 0 960 ${String(layout.height)}`}
                  className="min-h-[520px] min-w-[900px] w-full"
                  aria-label="Evidence correlation graph"
                  role="img"
                >
                  <g stroke="#24404e" strokeWidth="1.25">
                    {graphQuery.data.edges.map((edge) => {
                      const source = layout.positions.get(edge.source);
                      const target = layout.positions.get(edge.target);
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
                  {graphQuery.data.nodes.map((node) => {
                    const position = layout.positions.get(node.id);
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
                        onClick={() => { setSelectedId(node.id); }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedId(node.id);
                          }
                        }}
                      >
                        <circle
                          r={active ? 25 : 21}
                          fill={nodeColor(node.node_type)}
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
                {selected ? (
                  <NodeDetails node={selected} caseId={caseId} connected={connected.length} />
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
                {graphQuery.data.warnings.map((warning) => (
                  <p key={warning} className="text-xs leading-5 text-amber-100/75">{warning}</p>
                ))}
                <p className="mt-2 font-mono text-[10px] text-amber-100/45">
                  Graph SHA-256 {graphQuery.data.graph_hash}
                  {graphQuery.data.truncated ? " · display truncated by safety limits" : ""}
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function NodeDetails({
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
        <Link to={`/cases/${caseId}/evidence`} className="mt-5 inline-flex text-xs font-semibold text-cyan-200 hover:underline">
          Open acquired artifact
        </Link>
      )}
      {node.source_artifact_id && (
        <Link to={`/cases/${caseId}/evidence-twin`} className="mt-5 inline-flex text-xs font-semibold text-cyan-200 hover:underline">
          Open parsed source artifact
        </Link>
      )}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-slate-600">{label}</dt><dd className="mt-1 text-slate-300">{value}</dd></div>;
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
      <p className="text-[10px] uppercase tracking-[0.15em] text-slate-600">{label}</p>
      <p className="mt-2 text-xl font-semibold text-white">{value}</p>
    </div>
  );
}

function positionNodes(nodes: CorrelationNode[]) {
  const columns: CorrelationNodeType[][] = [
    ["device", "source"],
    ["artifact"],
    ["identity", "phone", "email", "application", "conversation", "domain", "network", "location"],
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

function nodeColor(type: CorrelationNodeType): string {
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
