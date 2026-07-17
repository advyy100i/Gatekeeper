"use client";

import { useState, useEffect, useCallback } from "react";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "@/components/ui/toaster";
import { api } from "@/lib/api";
import {
    BrainCircuit,
    Activity,
    AlertTriangle,
    Ban,
    RefreshCw,
    CheckCircle2,
    Timer,
    Eye,
    Gauge,
    Swords,
    Loader2,
    Radio,
    ShieldCheck,
} from "lucide-react";

interface AnomalyStatus {
    worker_alive: boolean;
    degraded_mode: boolean;
    mode: string;
    thresholds: { log: number; tarpit: number; block: number };
    weights: { global: number; per_key: number; enumeration: number; auth_abuse: number };
}

interface AnomalyScore {
    id: number;
    api_key_id: number;
    service_id: number;
    risk: number;
    action: string;
    endpoint: string | null;
    sub_scores: { global: number; per_key: number; enumeration: number; auth_abuse: number };
    timestamp: string | null;
}

interface AnomalyOverview {
    processed: number;
    allowed: number;
    flagged: number;
    allowed_pct: number;
    flagged_pct: number;
    source?: string;              // "replay" | "simulate" | "live_counters"
    replay_running: boolean;
    last_replay: {
        distinct_real_clients: number;
        injected_attack: {
            enabled: boolean;
            client_id: number | null;
            events: number;
            detected: number;
            recall: number;
        };
    } | null;
}

const ACTION_META: Record<string, { variant: "default" | "secondary" | "destructive" | "outline"; icon: typeof Eye; label: string }> = {
    block: { variant: "destructive", icon: Ban, label: "Blocked" },
    tarpit: { variant: "default", icon: Timer, label: "Tarpit" },
    log: { variant: "secondary", icon: Eye, label: "Logged" },
    allow: { variant: "outline", icon: CheckCircle2, label: "Allowed" },
};

function riskColor(risk: number): string {
    if (risk >= 0.9) return "text-red-500";
    if (risk >= 0.7) return "text-orange-500";
    if (risk >= 0.5) return "text-yellow-500";
    return "text-muted-foreground";
}

function SubScoreBar({ label, value }: { label: string; value: number }) {
    return (
        <div className="flex items-center gap-2">
            <span className="w-24 shrink-0 text-xs text-muted-foreground">{label}</span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                    className="h-full rounded-full bg-primary transition-all"
                    style={{ width: `${Math.round(Math.min(value, 1) * 100)}%` }}
                />
            </div>
            <span className="w-10 shrink-0 text-right text-xs font-mono tabular-nums">
                {value.toFixed(2)}
            </span>
        </div>
    );
}

export default function AnomalyPage() {
    const [status, setStatus] = useState<AnomalyStatus | null>(null);
    const [scores, setScores] = useState<AnomalyScore[]>([]);
    const [overview, setOverview] = useState<AnomalyOverview | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
    const [simulating, setSimulating] = useState(false);
    const [replaying, setReplaying] = useState(false);

    const fetchData = useCallback(async (showToast = false) => {
        try {
            const [statusData, scoresData, overviewData] = await Promise.all([
                api.getAnomalyStatus(),
                api.getAnomalyScores(100),
                api.getAnomalyOverview(),
            ]);
            setStatus(statusData);
            setScores(scoresData.scores);
            setOverview(overviewData);
            setReplaying(overviewData.replay_running);
            setLastUpdated(new Date());
            setError(null);
            if (showToast) toast.success("Threat data refreshed");
        } catch (err) {
            const msg = err instanceof Error ? err.message : "Failed to load anomaly data";
            setError(msg);
            if (showToast) toast.error(msg);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        // Poll faster while a real-traffic replay is streaming so the counters
        // visibly climb; otherwise a calm 5s live refresh.
        const t = setInterval(() => fetchData(), replaying ? 1500 : 5000);
        return () => clearInterval(t);
    }, [fetchData, replaying]);

    const runReplay = useCallback(async () => {
        setReplaying(true);
        try {
            const res = await api.replayRealTraffic(4000, true);
            toast.success(res.message);
            await fetchData();
        } catch (err) {
            const msg = err instanceof Error ? err.message : "Replay failed";
            toast.error(msg);
            setReplaying(false);
        }
    }, [fetchData]);

    const runSimulation = useCallback(async () => {
        setSimulating(true);
        try {
            const res = await api.simulateAnomalyAttack("all");
            const blockedTotal = res.results.reduce((a, r) => a + r.blocked, 0);
            const tarpitTotal = res.results.reduce((a, r) => a + r.tarpitted, 0);
            toast.success(
                `Simulated ${res.scenarios_run} attacks — ${blockedTotal} blocked, ${tarpitTotal} tarpitted`
            );
            await fetchData();
        } catch (err) {
            const msg = err instanceof Error ? err.message : "Simulation failed";
            toast.error(msg);
        } finally {
            setSimulating(false);
        }
    }, [fetchData]);

    const blocked = scores.filter((s) => s.action === "block").length;
    const tarpitted = scores.filter((s) => s.action === "tarpit").length;
    const flagged = scores.filter((s) => s.action === "log").length;

    return (
        <DashboardLayout>
            <div className="space-y-6">
                {/* Header */}
                <div className="flex items-start justify-between">
                    <div>
                        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
                            <BrainCircuit className="h-6 w-6 text-primary" />
                            Adaptive Threat Detection
                        </h1>
                        <p className="mt-1 text-sm text-muted-foreground">
                            AI behavioral anomaly detection — learns each key&apos;s normal usage and scores
                            every request in real time (credential stuffing, enumeration, low-and-slow scraping).
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={runReplay}
                            disabled={replaying}
                            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-60"
                            title="Stream real NASA-HTTP traffic through the live scorer"
                        >
                            {replaying ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                                <Radio className="h-4 w-4" />
                            )}
                            {replaying ? "Replaying real traffic…" : "Replay real traffic"}
                        </button>
                        <button
                            onClick={runSimulation}
                            disabled={simulating}
                            className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium transition-colors hover:bg-accent disabled:opacity-60"
                            title="Inject targeted synthetic attacks"
                        >
                            {simulating ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                                <Swords className="h-4 w-4" />
                            )}
                            {simulating ? "Simulating…" : "Simulate attack"}
                        </button>
                        <button
                            onClick={() => fetchData(true)}
                            className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium transition-colors hover:bg-accent"
                        >
                            <RefreshCw className="h-4 w-4" />
                        </button>
                    </div>
                </div>

                {error && (
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

                {/* How it works — plain-language explanation of everything on this page */}
                <details open className="rounded-lg border border-border bg-card">
                    <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium [&::-webkit-details-marker]:hidden">
                        <BrainCircuit className="h-4 w-4 text-primary" />
                        How this works — what every number on this page means
                        <span className="ml-auto text-xs font-normal text-muted-foreground">click to expand / collapse</span>
                    </summary>
                    <div className="space-y-5 border-t border-border px-4 py-4 text-sm">
                        <p className="text-muted-foreground">
                            Static gateway rules (API keys, rate limits) can&apos;t catch attacks that use a{" "}
                            <em>valid</em> key and look normal one request at a time — credential stuffing,
                            scraping, low-and-slow enumeration. This layer learns each key&apos;s{" "}
                            <strong className="text-foreground">normal behaviour</strong> and scores every
                            request in real time, adding restriction only when behaviour drifts.
                        </p>

                        <div>
                            <p className="mb-2 font-medium">Two detectors, combined into one risk score</p>
                            <div className="grid gap-3 sm:grid-cols-2">
                                <div className="rounded-md border border-border p-3">
                                    <p className="font-medium">Global model</p>
                                    <p className="mt-1 text-xs text-muted-foreground">
                                        &ldquo;Is this request unusual vs. <em>all</em> traffic?&rdquo; An online
                                        ML model (River HalfSpaceTrees) flags odd payload sizes, timing and bursts.
                                    </p>
                                </div>
                                <div className="rounded-md border border-border p-3">
                                    <p className="font-medium">Per-key baseline</p>
                                    <p className="mt-1 text-xs text-muted-foreground">
                                        &ldquo;Is this key behaving unlike <em>its own</em> history?&rdquo;
                                        Lightweight streaming stats per key — rate, timing, distinct IDs, failed-login ratio.
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div>
                            <p className="mb-2 font-medium">The four signals — the sub-scores shown on every decision</p>
                            <ul className="grid gap-2 sm:grid-cols-2">
                                <li className="text-xs"><span className="font-medium text-foreground">Global</span> — overall unusualness vs. the whole platform.</li>
                                <li className="text-xs"><span className="font-medium text-foreground">Per-key</span> — deviation from this key&apos;s normal request rate &amp; timing (a sudden speed-up).</li>
                                <li className="text-xs"><span className="font-medium text-foreground">Enumeration</span> — this key sweeping through many distinct IDs/endpoints (scraping, IDOR).</li>
                                <li className="text-xs"><span className="font-medium text-foreground">Auth abuse</span> — a spike in failed logins (401/403) = credential stuffing.</li>
                            </ul>
                            <p className="mt-2 text-xs text-muted-foreground">
                                Each signal is bounded 0–1 and combined with fixed weights; one highly-confident
                                signal can override the average, so a single-vector attack still fires.
                            </p>
                        </div>

                        <div>
                            <p className="mb-2 font-medium">Graduated response — not a binary switch</p>
                            <div className="flex flex-wrap gap-2 text-xs">
                                <span className="rounded-full border border-border px-2.5 py-1"><span className="text-muted-foreground">risk &lt; 0.5</span> → Allow</span>
                                <span className="rounded-full border border-border px-2.5 py-1"><span className="text-muted-foreground">0.5–0.7</span> → Log (watch)</span>
                                <span className="rounded-full border border-border px-2.5 py-1"><span className="text-orange-500">0.7–0.9</span> → Tarpit (add delay)</span>
                                <span className="rounded-full border border-border px-2.5 py-1"><span className="text-red-500">≥ 0.9</span> → Block (403)</span>
                            </div>
                        </div>

                        <div className="grid gap-3 sm:grid-cols-2">
                            <div className="rounded-md border border-border p-3">
                                <p className="text-xs font-medium">Why detection isn&apos;t instant or 100%</p>
                                <p className="mt-1 text-xs text-muted-foreground">
                                    The first few requests of an attack slip through before the behavioural signal
                                    crosses the threshold. That latency is deliberate — a detector that reacts to a
                                    single request would flag legitimate bursts. It&apos;s honest, not a flaw.
                                </p>
                            </div>
                            <div className="rounded-md border border-border p-3">
                                <p className="text-xs font-medium">Fail-open by design</p>
                                <p className="mt-1 text-xs text-muted-foreground">
                                    If the scoring engine is down, auth &amp; rate limits still protect you and traffic
                                    is allowed — a broken detector never blocks real users. The status bar shows
                                    &ldquo;Degraded&rdquo; then.
                                </p>
                            </div>
                        </div>

                        <div>
                            <p className="mb-2 font-medium">The two demo buttons</p>
                            <ul className="space-y-1.5">
                                <li className="text-xs">
                                    <span className="font-medium text-primary">Replay real traffic</span> — streams
                                    thousands of <em>real</em> HTTP requests (NASA-HTTP server logs) through the live
                                    scorer. ~98% are allowed, a tiny handful flagged, plus one attack injected from a
                                    real client (caught imperfectly — the realistic picture).
                                </li>
                                <li className="text-xs">
                                    <span className="font-medium text-foreground">Simulate attack</span> — injects
                                    targeted synthetic attacks (credential stuffing, enumeration, low-and-slow) to
                                    show clean, unambiguous detections.
                                </li>
                            </ul>
                        </div>
                    </div>
                </details>

                {/* Subsystem status */}
                {isLoading ? (
                    <Skeleton className="h-24 w-full" />
                ) : status ? (
                    <Card>
                        <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                            <div className="flex items-center gap-3">
                                {status.worker_alive ? (
                                    <span className="flex h-2.5 w-2.5 rounded-full bg-green-500 shadow-[0_0_8px] shadow-green-500" />
                                ) : (
                                    <span className="flex h-2.5 w-2.5 rounded-full bg-yellow-500" />
                                )}
                                <div>
                                    <p className="text-sm font-medium">
                                        Scoring engine: {status.worker_alive ? "Active" : "Degraded (fail-open)"}
                                    </p>
                                    <p className="text-xs text-muted-foreground">{status.mode}</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-6 text-sm">
                                <div className="flex items-center gap-2">
                                    <Gauge className="h-4 w-4 text-muted-foreground" />
                                    <span className="text-muted-foreground">Thresholds</span>
                                    <span className="font-mono">
                                        log {status.thresholds.log} · tarpit {status.thresholds.tarpit} · block {status.thresholds.block}
                                    </span>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                ) : null}

                {/* Traffic overview — the believable allowed-vs-flagged picture */}
                {overview && overview.processed > 0 && (
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between">
                            <div>
                                <CardTitle className="flex items-center gap-2 text-base">
                                    <ShieldCheck className="h-4 w-4 text-green-500" />
                                    Traffic overview
                                    <Badge variant="outline" className="font-normal">
                                        {overview.source === "replay"
                                            ? "last run: real-traffic replay"
                                            : overview.source === "simulate"
                                                ? "last run: simulated attack"
                                                : "live"}
                                    </Badge>
                                </CardTitle>
                                <CardDescription>
                                    {overview.source === "replay" && overview.last_replay ? (
                                        <>
                                            {overview.processed.toLocaleString()} real requests scored across{" "}
                                            {overview.last_replay.distinct_real_clients.toLocaleString()} real client IPs
                                            (NASA-HTTP). The overwhelming majority is allowed — flags are the rare,
                                            genuine anomalies plus the one injected attack.
                                        </>
                                    ) : overview.source === "simulate" ? (
                                        <>
                                            {overview.processed.toLocaleString()} requests from a targeted{" "}
                                            <em>attack simulation</em> (warmup + credential stuffing, enumeration,
                                            low-and-slow). Flagged events are the injected attacks — this is a stress
                                            test, not representative traffic.
                                        </>
                                    ) : (
                                        <>{overview.processed.toLocaleString()} requests scored live.</>
                                    )}
                                </CardDescription>
                            </div>
                            {replaying && (
                                <span className="flex items-center gap-1.5 text-xs text-primary">
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                    streaming…
                                </span>
                            )}
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-end gap-6">
                                <div>
                                    <p className="text-3xl font-semibold tabular-nums text-green-500">
                                        {overview.allowed_pct}%
                                    </p>
                                    <p className="text-xs text-muted-foreground">allowed</p>
                                </div>
                                <div>
                                    <p className="text-3xl font-semibold tabular-nums text-orange-500">
                                        {overview.flagged_pct}%
                                    </p>
                                    <p className="text-xs text-muted-foreground">
                                        flagged ({overview.flagged.toLocaleString()} of {overview.processed.toLocaleString()})
                                    </p>
                                </div>
                            </div>
                            {/* stacked allowed/flagged bar */}
                            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted">
                                <div className="h-full bg-green-500" style={{ width: `${overview.allowed_pct}%` }} />
                                <div className="h-full bg-orange-500" style={{ width: `${Math.max(overview.flagged_pct, overview.flagged > 0 ? 0.5 : 0)}%` }} />
                            </div>
                            {overview.last_replay?.injected_attack.enabled && (
                                <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
                                    <p className="flex items-center gap-2 font-medium">
                                        <Swords className="h-4 w-4 text-orange-500" />
                                        Injected attack (from a previously-benign real client #{overview.last_replay.injected_attack.client_id})
                                    </p>
                                    <p className="mt-1 text-muted-foreground">
                                        Caught{" "}
                                        <span className="font-semibold text-foreground">
                                            {overview.last_replay.injected_attack.detected}/{overview.last_replay.injected_attack.events}
                                        </span>{" "}
                                        events ({Math.round(overview.last_replay.injected_attack.recall * 100)}% recall) — detection
                                        has latency, so the first requests slip through before the behavioral
                                        signal crosses the threshold. Not a scripted 100%.
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                )}

                {/* Stat tiles */}
                <div className="grid gap-4 sm:grid-cols-3">
                    <StatTile icon={Ban} label="Blocked" value={blocked} tone="text-red-500" loading={isLoading} />
                    <StatTile icon={Timer} label="Tarpitted" value={tarpitted} tone="text-orange-500" loading={isLoading} />
                    <StatTile icon={Eye} label="Flagged (logged)" value={flagged} tone="text-yellow-500" loading={isLoading} />
                </div>

                {/* Fusion weights */}
                {status && (
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-base">Risk fusion weights</CardTitle>
                            <CardDescription>
                                Four bounded detectors combined into one risk score, with a strong-single-detector
                                override for single-vector attacks.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="grid gap-2 sm:grid-cols-2">
                            <SubScoreBar label="Global (HST)" value={status.weights.global} />
                            <SubScoreBar label="Per-key" value={status.weights.per_key} />
                            <SubScoreBar label="Enumeration" value={status.weights.enumeration} />
                            <SubScoreBar label="Auth abuse" value={status.weights.auth_abuse} />
                        </CardContent>
                    </Card>
                )}

                {/* Recent decisions */}
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                            <CardTitle className="text-base">Recent risk decisions</CardTitle>
                            <CardDescription>
                                Elevated-risk requests (risk ≥ log threshold), newest first. Every decision is
                                explainable via its sub-scores.
                            </CardDescription>
                        </div>
                        {lastUpdated && (
                            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <Activity className="h-3 w-3" />
                                live · {lastUpdated.toLocaleTimeString()}
                            </span>
                        )}
                    </CardHeader>
                    <CardContent>
                        {isLoading ? (
                            <div className="space-y-3">
                                {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
                            </div>
                        ) : scores.length === 0 ? (
                            <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
                                <CheckCircle2 className="h-8 w-8 text-green-500" />
                                <p className="text-sm font-medium">No elevated-risk activity</p>
                                <p className="text-xs text-muted-foreground">
                                    All traffic is scoring below the log threshold. Click
                                    <span className="font-medium text-foreground"> Simulate attack </span>
                                    above to drive credential-stuffing, enumeration and low-and-slow
                                    traffic through the live scorer and watch it get flagged.
                                </p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {scores.map((s) => {
                                    const meta = ACTION_META[s.action] ?? ACTION_META.allow;
                                    const Icon = meta.icon;
                                    return (
                                        <div
                                            key={s.id}
                                            className="grid gap-3 rounded-lg border border-border p-3 sm:grid-cols-[1fr_1.4fr]"
                                        >
                                            <div className="space-y-1">
                                                <div className="flex items-center gap-2">
                                                    <Badge variant={meta.variant} className="gap-1">
                                                        <Icon className="h-3 w-3" />
                                                        {meta.label}
                                                    </Badge>
                                                    <span className={`text-lg font-semibold tabular-nums ${riskColor(s.risk)}`}>
                                                        {(s.risk * 100).toFixed(0)}%
                                                    </span>
                                                    <span className="text-xs text-muted-foreground">risk</span>
                                                </div>
                                                <p className="truncate font-mono text-xs text-muted-foreground">
                                                    key #{s.api_key_id} · svc #{s.service_id}
                                                    {s.endpoint ? ` · ${s.endpoint}` : ""}
                                                </p>
                                                <p className="text-xs text-muted-foreground">
                                                    {s.timestamp ? new Date(s.timestamp).toLocaleString() : "—"}
                                                </p>
                                            </div>
                                            <div className="space-y-1.5">
                                                <SubScoreBar label="Global" value={s.sub_scores.global} />
                                                <SubScoreBar label="Per-key" value={s.sub_scores.per_key} />
                                                <SubScoreBar label="Enumeration" value={s.sub_scores.enumeration} />
                                                <SubScoreBar label="Auth abuse" value={s.sub_scores.auth_abuse} />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </DashboardLayout>
    );
}

function StatTile({
    icon: Icon,
    label,
    value,
    tone,
    loading,
}: {
    icon: typeof Ban;
    label: string;
    value: number;
    tone: string;
    loading: boolean;
}) {
    return (
        <Card>
            <CardContent className="flex items-center justify-between py-5">
                <div>
                    <p className="text-sm text-muted-foreground">{label}</p>
                    {loading ? (
                        <Skeleton className="mt-1 h-8 w-12" />
                    ) : (
                        <p className={`text-2xl font-semibold tabular-nums ${tone}`}>{value}</p>
                    )}
                </div>
                <Icon className={`h-8 w-8 ${tone} opacity-80`} />
            </CardContent>
        </Card>
    );
}
