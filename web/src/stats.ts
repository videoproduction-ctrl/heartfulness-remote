// Connection statistics for the latency pill (RTT, fps, Mbps, direct/relay).

export type Level = "good" | "ok" | "bad" | "unknown";

/** green < 40 ms, amber < 100 ms, red ≥ 100 ms. */
export function latencyLevel(ms: number | null | undefined): Level {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "unknown";
  if (ms < 40) return "good";
  if (ms < 100) return "ok";
  return "bad";
}

export interface RawStat {
  id: string;
  type: string;
  [k: string]: unknown;
}

export interface Snapshot {
  t: number; // ms
  bytes: number;
  framesDecoded: number | null;
  fps: number | null;
  iceRttMs: number | null;
  relay: boolean | null;
  codec: string | null;
  width: number | null;
  height: number | null;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Extracts what we need from an RTCStatsReport (passed as a list of stats objects). */
export function snapshot(stats: Iterable<RawStat>, t: number): Snapshot {
  const byId = new Map<string, RawStat>();
  for (const s of stats) byId.set(s.id, s);
  let bytes = 0;
  let framesDecoded: number | null = null;
  let fps: number | null = null;
  let codec: string | null = null;
  let width: number | null = null;
  let height: number | null = null;
  let pair: RawStat | undefined;
  for (const s of byId.values()) {
    if (s.type === "inbound-rtp") {
      bytes += num(s["bytesReceived"]) ?? 0;
      if (s["kind"] === "video" || s["mediaType"] === "video") {
        framesDecoded = num(s["framesDecoded"]);
        fps = num(s["framesPerSecond"]);
        width = num(s["frameWidth"]);
        height = num(s["frameHeight"]);
        const c = typeof s["codecId"] === "string" ? byId.get(s["codecId"]) : undefined;
        if (c && typeof c["mimeType"] === "string") codec = c["mimeType"].replace(/^video\//i, "");
      }
    } else if (s.type === "transport" && typeof s["selectedCandidatePairId"] === "string") {
      pair = byId.get(s["selectedCandidatePairId"]) ?? pair;
    }
  }
  if (!pair) {
    for (const s of byId.values()) {
      if (s.type !== "candidate-pair") continue;
      if (s["selected"] === true || (s["nominated"] === true && s["state"] === "succeeded")) {
        pair = s;
        break;
      }
    }
  }
  let iceRttMs: number | null = null;
  let relay: boolean | null = null;
  if (pair) {
    const rtt = num(pair["currentRoundTripTime"]);
    iceRttMs = rtt === null ? null : rtt * 1000;
    const l = typeof pair["localCandidateId"] === "string" ? byId.get(pair["localCandidateId"]) : undefined;
    const r = typeof pair["remoteCandidateId"] === "string" ? byId.get(pair["remoteCandidateId"]) : undefined;
    if (l || r) relay = l?.["candidateType"] === "relay" || r?.["candidateType"] === "relay";
  }
  return { t, bytes, framesDecoded, fps, iceRttMs, relay, codec, width, height };
}

export function rates(prev: Snapshot | null, cur: Snapshot): { mbps: number | null; fps: number | null } {
  if (!prev || cur.t <= prev.t) return { mbps: null, fps: cur.fps };
  const dt = (cur.t - prev.t) / 1000;
  const mbps = cur.bytes >= prev.bytes ? ((cur.bytes - prev.bytes) * 8) / dt / 1e6 : null;
  let fps = cur.fps;
  if (fps === null && cur.framesDecoded !== null && prev.framesDecoded !== null && cur.framesDecoded >= prev.framesDecoded) {
    fps = (cur.framesDecoded - prev.framesDecoded) / dt;
  }
  return { mbps, fps };
}
