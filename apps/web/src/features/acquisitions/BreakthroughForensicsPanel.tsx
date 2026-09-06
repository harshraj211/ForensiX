import React, { useState } from "react";
import {
  Activity,
  Cloud,
  Cpu,
  Database,
  Disc,
  FileCheck,
  HardDrive,
  Video,
  Zap,
} from "lucide-react";
import {
  mountPhysicalImage,
  recordLiveTouch,
  replayCloudTokens,
  scanTimelineAnomalies,
  type CloudTokenReplayResult,
  type LiveTouchRecordResult,
  type PhysicalImageMountResult,
  type TimelineAnomalyResult,
} from "../../lib/api";

interface BreakthroughForensicsPanelProps {
  caseId: string;
  serial: string;
}

export const BreakthroughForensicsPanel: React.FC<BreakthroughForensicsPanelProps> = ({
  caseId,
  serial,
}) => {
  // Cloud Replay State
  const [cloudLoading, setCloudLoading] = useState<boolean>(false);
  const [cloudResult, setCloudResult] = useState<CloudTokenReplayResult | null>(null);

  // Live Touch State
  const [touchLoading, setTouchLoading] = useState<boolean>(false);
  const [touchResult, setTouchResult] = useState<LiveTouchRecordResult | null>(null);

  // Timeline Anomaly State
  const [anomalyLoading, setAnomalyLoading] = useState<boolean>(false);
  const [anomalyResult, setAnomalyResult] = useState<TimelineAnomalyResult | null>(null);

  // Physical Mount State
  const [mountLoading, setMountLoading] = useState<boolean>(false);
  const [mountResult, setMountResult] = useState<PhysicalImageMountResult | null>(null);

  const handleCloudReplay = async () => {
    setCloudLoading(true);
    try {
      const res = await replayCloudTokens(caseId, { serial, case_id: caseId });
      setCloudResult(res);
    } catch (err) {
      console.error("Cloud replay failed", err);
    } finally {
      setCloudLoading(false);
    }
  };

  const handleRecordLiveTouch = async () => {
    setTouchLoading(true);
    try {
      const res = await recordLiveTouch(caseId, { serial, case_id: caseId, duration_sec: 15 });
      setTouchResult(res);
    } catch (err) {
      console.error("Live touch record failed", err);
    } finally {
      setTouchLoading(false);
    }
  };

  const handleScanAnomalies = async () => {
    setAnomalyLoading(true);
    try {
      const res = await scanTimelineAnomalies(caseId, { serial, case_id: caseId });
      setAnomalyResult(res);
    } catch (err) {
      console.error("Timeline anomaly scan failed", err);
    } finally {
      setAnomalyLoading(false);
    }
  };

  const handleMountImage = async () => {
    setMountLoading(true);
    try {
      const res = await mountPhysicalImage(caseId, { serial, case_id: caseId });
      setMountResult(res);
    } catch (err) {
      console.error("Physical image mount failed", err);
    } finally {
      setMountLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl bg-gradient-to-r from-slate-900 via-sky-950 to-slate-900 p-6 text-white border border-sky-500/30 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-sky-600/30 rounded-lg border border-sky-400/40">
              <Disc className="w-7 h-7 text-sky-400 animate-spin" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                Tier-1 Breakthrough Forensic Suite
                <span className="text-xs px-2 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/40 font-mono">
                  Cloud, Touch & Inode Master
                </span>
              </h2>
              <p className="text-sm text-slate-300">
                Cloud Token Replay, 60fps MP4 Touch Coordinate Mapper, Timeline Anomaly Detector & EXT4 Inode Carver.
              </p>
            </div>
          </div>
          <div className="text-xs font-mono text-sky-300 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            Target Serial: <strong>{serial || "CONNECTED_ADB"}</strong>
          </div>
        </div>
      </div>

      {/* 4 Execution Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Cloud Token Replay */}
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-3">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
                <Cloud className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/40">
                NO 2FA REQ
              </span>
            </div>
            <h3 className="text-xs font-bold text-slate-900 dark:text-white">
              Cloud Token Replay Engine
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
              Syncs Google Drive WhatsApp backups, Telegram Cloud messages & Google Timeline via harvested session tokens.
            </p>
          </div>

          <button
            onClick={handleCloudReplay}
            disabled={cloudLoading}
            className="w-full py-2 bg-sky-600 hover:bg-sky-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
          >
            {cloudLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Cloud className="w-3.5 h-3.5" />
                <span>Sync Cloud Backups</span>
              </>
            )}
          </button>
        </div>

        {/* Card 2: Live Touch Mapper */}
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-3">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30">
                <Video className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                60FPS VIDEO
              </span>
            </div>
            <h3 className="text-xs font-bold text-slate-900 dark:text-white">
              Live Touch Gesture Mapper
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
              Streams 60fps MP4 video via scrcpy with raw ADB touch coordinate overlays (/dev/input/event*).
            </p>
          </div>

          <button
            onClick={handleRecordLiveTouch}
            disabled={touchLoading}
            className="w-full py-2 bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
          >
            {touchLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Video className="w-3.5 h-3.5" />
                <span>Record 15s Touch Feed</span>
              </>
            )}
          </button>
        </div>

        {/* Card 3: Timeline Anomaly Detector */}
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-3">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30">
                <Activity className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                ALIBI VERIFIER
              </span>
            </div>
            <h3 className="text-xs font-bold text-slate-900 dark:text-white">
              Timeline Anomaly Detector
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
              Flags chat silence gaps, midnight bursts, clock rollbacks, and EXIF GPS spoofing jumps.
            </p>
          </div>

          <button
            onClick={handleScanAnomalies}
            disabled={anomalyLoading}
            className="w-full py-2 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
          >
            {anomalyLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Activity className="w-3.5 h-3.5" />
                <span>Scan Timeline Anomalies</span>
              </>
            )}
          </button>
        </div>

        {/* Card 4: Physical Image Mounter */}
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-3">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                <HardDrive className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                EXT4 / F2FS
              </span>
            </div>
            <h3 className="text-xs font-bold text-slate-900 dark:text-white">
              Physical Image Inode Carver
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
              Parses EXT4/F2FS superblocks & inode tables to carve deleted files from unallocated sectors.
            </p>
          </div>

          <button
            onClick={handleMountImage}
            disabled={mountLoading}
            className="w-full py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
          >
            {mountLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Cpu className="w-3.5 h-3.5" />
                <span>Carve Image Inodes</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Result Cards */}
      {cloudResult && (
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-sky-400 flex items-center gap-2">
              <Cloud className="w-4 h-4" />
              Cloud Token Replay Sync Results
            </span>
            <span className="text-slate-400">Downloaded: {(cloudResult.total_bytes_downloaded / 1024 / 1024).toFixed(2)} MB</span>
          </div>

          <div className="space-y-1.5">
            {cloudResult.synced_services.map((svc, idx) => (
              <div key={idx} className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 flex items-center justify-between">
                <div>
                  <div className="font-bold text-slate-900 dark:text-white">{svc.service_name} ({svc.target_account})</div>
                  <div className="text-[11px] text-slate-400">Token: {svc.token_type}</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 font-bold text-[10px]">
                  {svc.synced_artifacts_count} artifacts
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {touchResult && (
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-purple-400 flex items-center gap-2">
              <Video className="w-4 h-4" />
              Live Touch Video Recording Complete
            </span>
            <span className="text-emerald-400 font-bold">🛡️ {touchResult.sha256_seal}</span>
          </div>
          <p className="text-slate-300">
            Exported {touchResult.fps} FPS video to <strong>{touchResult.video_output_path}</strong> with {touchResult.total_touch_events_mapped} mapped touch gesture overlays.
          </p>
        </div>
      )}

      {anomalyResult && (
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-rose-400 flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Timeline Anomaly Scan Results (Alibi Score: {(anomalyResult.alibi_verification_score * 100).toFixed(0)}%)
            </span>
            <span className="text-slate-400">Analyzed {anomalyResult.total_events_analyzed} Events</span>
          </div>

          <div className="space-y-2">
            {anomalyResult.anomalies_detected.map((a) => (
              <div key={a.anomaly_id} className="p-3 rounded bg-slate-50 dark:bg-slate-950 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-400">{a.anomaly_type}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40">
                    {a.severity}
                  </span>
                </div>
                <p className="text-slate-200">{a.description}</p>
                <div className="text-[11px] text-slate-400">Artifact: {a.affected_artifact} | Range: {a.timestamp_range}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {mountResult && (
        <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-cyan-400 flex items-center gap-2">
              <HardDrive className="w-4 h-4" />
              Physical Image Inode Carving Results ({mountResult.filesystem_type})
            </span>
            <span className="text-slate-400">Scanned {mountResult.total_inodes_scanned} Inodes</span>
          </div>

          <div className="space-y-1.5">
            {mountResult.carved_inodes.map((item) => (
              <div key={item.inode_number} className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 flex items-center justify-between">
                <div>
                  <div className="font-bold text-slate-900 dark:text-white">Inode #{item.inode_number}: {item.file_name}</div>
                  <div className="text-[11px] text-slate-400">Blocks: {item.unallocated_block_range} | Hash: {item.sha256_hash.slice(0, 12)}...</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-[10px]">
                  {item.file_type} ({(item.size_bytes / 1024).toFixed(1)} KB)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
