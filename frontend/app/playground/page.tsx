import { API_BASE_URL } from "@/lib/api";
"use client";

import { useState, useEffect } from "react";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/toaster";
import { Skeleton } from "@/components/ui/skeleton";
import { api, getApiKey } from "@/lib/api";
import {
  Play,
  Send,
  Clock,
  CheckCircle2,
  XCircle,
  Copy,
  RefreshCw,
  Loader2,
  Zap,
  Code,
  ChevronDown
} from "lucide-react";

interface ServiceData {
  id: number;
  name: string;
  target_url: string;
  watermarking_enabled: boolean;
}

interface ApiKeyData {
  id: number;
  key_masked: string;
  is_active: boolean;
}

interface ServiceWithKeys {
  service_id: number;
  service_name: string;
  api_keys: ApiKeyData[];
}

interface RequestResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  duration: number;
  timestamp: string;
}

export default function PlaygroundPage() {
  const [services, setServices] = useState<ServiceData[]>([]);
  const [servicesWithKeys, setServicesWithKeys] = useState<ServiceWithKeys[]>([]);
  const [isLoadingServices, setIsLoadingServices] = useState(true);
  
  const [selectedServiceId, setSelectedServiceId] = useState<number | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [method, setMethod] = useState<"GET" | "POST" | "PUT" | "DELETE">("GET");
  const [pathSuffix, setPathSuffix] = useState("");
  const [requestBody, setRequestBody] = useState("");
  
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<RequestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
    // Try to get stored API key
    const storedKey = getApiKey();
    if (storedKey) {
      setApiKey(storedKey);
    }
  }, []);

  const fetchData = async () => {
    setIsLoadingServices(true);
    try {
      const [servicesData, keysData] = await Promise.all([
        api.listServices(),
        api.listAllApiKeys()
      ]);
      setServices(servicesData.services);
      setServicesWithKeys(keysData.services);
      
      // Auto-select first service
      if (servicesData.services.length > 0 && !selectedServiceId) {
        setSelectedServiceId(servicesData.services[0].id);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to load data";
      toast.error(errorMessage);
    } finally {
      setIsLoadingServices(false);
    }
  };

  const handleSendRequest = async () => {
    if (!selectedServiceId) {
      toast.error("Please select a service");
      return;
    }
    if (!apiKey.trim()) {
      toast.error("Please enter an API key");
      return;
    }

    setIsLoading(true);
    setResult(null);
    setError(null);

    const startTime = Date.now();
    // Build proxy URL with optional path suffix
    let proxyUrl = `${API_BASE_URL}/proxy/${selectedServiceId}`;
    if (pathSuffix.trim()) {
      const cleanPath = pathSuffix.trim().replace(/^\/+/, '');
      proxyUrl = `${proxyUrl}/${cleanPath}`;
    }

    try {
      const options: RequestInit = {
        method,
        headers: {
          "X-API-Key": apiKey,
          "Content-Type": "application/json",
        },
      };

      if (method !== "GET" && requestBody.trim()) {
        options.body = requestBody;
      }

      const response = await fetch(proxyUrl, options);
      const duration = Date.now() - startTime;
      
      // Get response body
      let body = "";
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const jsonData = await response.json();
        body = JSON.stringify(jsonData, null, 2);
      } else {
        body = await response.text();
      }

      // Get response headers
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      setResult({
        status: response.status,
        statusText: response.statusText,
        headers,
        body,
        duration,
        timestamp: new Date().toISOString(),
      });

      if (response.ok) {
        toast.success(`Request successful (${response.status})`);
      } else {
        toast.warning(`Request returned ${response.status}`);
      }
    } catch (err) {
      const duration = Date.now() - startTime;
      const errorMessage = err instanceof Error ? err.message : "Request failed";
      setError(errorMessage);
      setResult({
        status: 0,
        statusText: "Error",
        headers: {},
        body: errorMessage,
        duration,
        timestamp: new Date().toISOString(),
      });
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const copyResponse = () => {
    if (result) {
      navigator.clipboard.writeText(result.body);
      toast.success("Response copied to clipboard");
    }
  };

  const getSelectedService = () => {
    return services.find(s => s.id === selectedServiceId);
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return "text-green-500";
    if (status >= 300 && status < 400) return "text-blue-500";
    if (status >= 400 && status < 500) return "text-orange-500";
    if (status >= 500) return "text-red-500";
    return "text-muted-foreground";
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        {/* Header */}
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">API Playground</h1>
          <p className="text-muted-foreground text-sm">
            Test your APIs directly through the gateway
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Request Builder */}
          <Card className="border-border/50 bg-card/50 backdrop-blur">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                  <Send className="h-5 w-5 text-blue-500" />
                </div>
                <div>
                  <CardTitle>Request Builder</CardTitle>
                  <CardDescription className="text-xs">
                    Configure and send API requests
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Service Selection */}
              <div className="space-y-2">
                <Label className="text-sm">Service</Label>
                {isLoadingServices ? (
                  <Skeleton className="h-10 w-full" />
                ) : services.length === 0 ? (
                  <Alert>
                    <AlertDescription className="text-sm">
                      No services registered. Register an API first.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <select
                    value={selectedServiceId || ""}
                    onChange={(e) => setSelectedServiceId(Number(e.target.value))}
                    className="w-full h-10 px-3 rounded-md border border-input bg-background text-sm"
                  >
                    <option value="">Select a service...</option>
                    {services.map((service) => (
                      <option key={service.id} value={service.id}>
                        {service.name} (ID: {service.id})
                      </option>
                    ))}
                  </select>
                )}
                {getSelectedService() && (
                  <div className="text-xs text-muted-foreground space-y-1">
                    <p>Base URL: <code className="bg-muted px-1 rounded">{getSelectedService()?.target_url}</code></p>
                    {pathSuffix.trim() && (
                      <p>Full URL: <code className="bg-muted px-1 rounded">{getSelectedService()?.target_url.replace(/\/+$/, '')}/{pathSuffix.trim().replace(/^\/+/, '')}</code></p>
                    )}
                  </div>
                )}
              </div>

              {/* API Key */}
              <div className="space-y-2">
                <Label className="text-sm">API Key</Label>
                <Input
                  type="password"
                  placeholder="Enter your API key"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Use an API key created for the selected service
                </p>
              </div>

              {/* Method */}
              <div className="space-y-2">
                <Label className="text-sm">Method</Label>
                <div className="flex gap-2">
                  {(["GET", "POST", "PUT", "DELETE"] as const).map((m) => (
                    <Button
                      key={m}
                      variant={method === m ? "default" : "outline"}
                      size="sm"
                      onClick={() => setMethod(m)}
                      className={method === m ? "" : ""}
                    >
                      {m}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Path Suffix */}
              <div className="space-y-2">
                <Label className="text-sm">Path (optional)</Label>
                <Input
                  type="text"
                  placeholder="/users/1 or posts/2"
                  value={pathSuffix}
                  onChange={(e) => setPathSuffix(e.target.value)}
                  className="font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Additional path to append to the target URL
                </p>
              </div>

              {/* Request Body (for POST/PUT) */}
              {(method === "POST" || method === "PUT") && (
                <div className="space-y-2">
                  <Label className="text-sm">Request Body (JSON)</Label>
                  <Textarea
                    placeholder='{"key": "value"}'
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    className="min-h-[100px] font-mono text-xs"
                  />
                </div>
              )}

              {/* Send Button */}
              <Button
                onClick={handleSendRequest}
                disabled={isLoading || !selectedServiceId || !apiKey.trim()}
                className="w-full"
                size="lg"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Sending...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Send Request
                  </>
                )}
              </Button>

              {/* Request Preview */}
              {selectedServiceId && (
                <div className="rounded-md border border-border/50 bg-muted/30 p-3">
                  <p className="text-xs text-muted-foreground mb-1">Request URL</p>
                  <code className="text-xs font-mono">
                    {method} ${API_BASE_URL}/proxy/{selectedServiceId}
                  </code>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Response Viewer */}
          <Card className="border-border/50 bg-card/50 backdrop-blur">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                    <Code className="h-5 w-5 text-green-500" />
                  </div>
                  <div>
                    <CardTitle>Response</CardTitle>
                    <CardDescription className="text-xs">
                      View the API response
                    </CardDescription>
                  </div>
                </div>
                {result && (
                  <Button variant="ghost" size="sm" onClick={copyResponse}>
                    <Copy className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!result && !isLoading && (
                <div className="rounded-md border border-dashed border-border/50 p-12 text-center">
                  <Zap className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm font-medium mb-1">No response yet</p>
                  <p className="text-xs text-muted-foreground">
                    Send a request to see the response here
                  </p>
                </div>
              )}

              {isLoading && (
                <div className="space-y-3">
                  <Skeleton className="h-8 w-32" />
                  <Skeleton className="h-[200px] w-full" />
                </div>
              )}

              {result && !isLoading && (
                <div className="space-y-4">
                  {/* Status Bar */}
                  <div className="flex items-center justify-between p-3 rounded-md bg-muted/30 border border-border/50">
                    <div className="flex items-center gap-3">
                      {result.status >= 200 && result.status < 300 ? (
                        <CheckCircle2 className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-500" />
                      )}
                      <span className={`text-lg font-mono font-bold ${getStatusColor(result.status)}`}>
                        {result.status || "ERR"}
                      </span>
                      <span className="text-sm text-muted-foreground">
                        {result.statusText}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Clock className="h-4 w-4" />
                      {result.duration}ms
                    </div>
                  </div>

                  {/* Response Body */}
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Response Body</Label>
                    <pre className="rounded-md border border-border/50 bg-muted/30 p-4 text-xs font-mono overflow-auto max-h-[400px] whitespace-pre-wrap">
                      {result.body || "(empty response)"}
                    </pre>
                  </div>

                  {/* Watermark Indicator */}
                  {result.body.includes("_gaas_watermark") && (
                    <Alert className="border-purple-500/50 bg-purple-500/5">
                      <AlertDescription className="text-sm text-purple-600 dark:text-purple-400 flex items-center gap-2">
                        <Badge className="bg-purple-500/20 text-purple-500 border-purple-500/30">
                          Watermarked
                        </Badge>
                        This response contains a watermark for leak attribution
                      </AlertDescription>
                    </Alert>
                  )}

                  {/* Timestamp */}
                  <p className="text-xs text-muted-foreground text-right">
                    {new Date(result.timestamp).toLocaleString()}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Quick Tips */}
        <Card className="border-border/50 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="text-base">Quick Tips</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-1">
                <p className="text-sm font-medium">1. Select a Service</p>
                <p className="text-xs text-muted-foreground">
                  Choose the registered API you want to test from the dropdown.
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium">2. Enter API Key</p>
                <p className="text-xs text-muted-foreground">
                  Use an API key created for that service (from Settings page).
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium">3. Check Watermark</p>
                <p className="text-xs text-muted-foreground">
                  If watermarking is enabled, the response will include a _gaas_watermark field.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
