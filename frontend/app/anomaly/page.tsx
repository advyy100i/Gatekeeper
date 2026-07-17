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
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

    const fetchData = useCallback(async (showToast = false) => {
        try {
            const [statusData, scoresData] = await Promise.all([
                api.getAnomalyStatus(),
                api.getAnomalyScores(100),
            ]);
            setStatus(statusData);
            setScores(scoresData.scores);
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
        const t = setInterval(() => fetchData(), 5000); // live auto-refresh
        return () => clearInterval(t);
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
                    <button
                        onClick={() => fetchData(true)}
                        className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium transition-colors hover:bg-accent"
                    >
                        <RefreshCw className="h-4 w-4" />
                        Refresh
                    </button>
                </div>

                {error && (
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

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
                                    All traffic is scoring below the log threshold. Drive some abusive traffic
                                    (or run the evaluator) to see decisions here.
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
