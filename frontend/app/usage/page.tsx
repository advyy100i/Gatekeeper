"use client";

import { useState, useEffect } from "react";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "@/components/ui/toaster";
import { getApiKey, setApiKey } from "@/lib/api";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  BarChart3,
  Activity,
  Loader2,
  AlertCircle,
  RefreshCw,
  TrendingUp
} from "lucide-react";

interface UsageStats {
  service_id: number;
  total_requests: number;
  requests_by_api_key: Array<{
    api_key: string;
    count: number;
  }>;
}

/**
 * Extract service ID from either a numeric string or Gateway URL
 * 
 * Examples:
 * - "2" → 2
 * - "/proxy/2" → 2
 * - "${API_BASE_URL}/proxy/2" → 2
 * - "http://localhost:8000/proxy/123" → 123
 * 
 * @param input - Service ID number or Gateway URL
 * @returns Extracted service ID number or null if invalid
 */
function extractServiceId(input: string): number | null {
  if (!input || !input.trim()) {
    return null;
  }

  const trimmed = input.trim();

  // Check if it's a plain number
  const numericMatch = trimmed.match(/^\d+$/);
  if (numericMatch) {
    const id = parseInt(numericMatch[0], 10);
    return isNaN(id) || id <= 0 ? null : id;
  }

  // Check if it's a Gateway URL (e.g., /proxy/2 or http://.../proxy/2)
  const urlPattern = /\/proxy\/(\d+)(?:\/|$|\?|#)/;
  const match = trimmed.match(urlPattern);
  if (match && match[1]) {
    const id = parseInt(match[1], 10);
    return isNaN(id) || id <= 0 ? null : id;
  }

  return null;
}

/**
 * Validate input and return a user-friendly error message if invalid
 */
function validateInput(input: string): string | null {
  if (!input || !input.trim()) {
    return "Please enter a Service ID or Gateway URL";
  }

  const serviceId = extractServiceId(input);
  if (serviceId === null) {
    return "Invalid input. Please enter a Service ID (e.g., 2) or Gateway URL (e.g., /proxy/2)";
  }

  return null;
}

export default function UsagePage() {
  const [input, setInput] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [rememberKey, setRememberKey] = useState(false);
  const [usageData, setUsageData] = useState<UsageStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-fetch on mount if we have a service ID in URL params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("service_id");
    if (id) {
      setInput(id);
    }
    
    // Pre-fill API key from localStorage if available
    const storedApiKey = getApiKey();
    if (storedApiKey) {
      setApiKeyInput(storedApiKey);
    }
  }, []);

  const fetchUsageData = async () => {
    // Clear previous errors
    setError(null);

    // Validate input
    const validationError = validateInput(input);
    if (validationError) {
      setError(validationError);
      toast.error(validationError);
      return;
    }

    // Extract service ID
    const serviceId = extractServiceId(input);
    if (serviceId === null) {
      const errorMsg = "Failed to extract Service ID from input";
      setError(errorMsg);
      toast.error(errorMsg);
      return;
    }

    // Validate API key input
    const apiKey = apiKeyInput.trim();
    if (!apiKey) {
      const errorMsg = "Please enter an API key";
      setError(errorMsg);
      toast.error(errorMsg);
      return;
    }

    // Save API key to localStorage if "Remember this key" is checked
    if (rememberKey) {
      setApiKey(apiKey);
      toast.success("API key saved");
    }

    setIsLoading(true);

    try {
      // Send GET request to /usage/{service_id} with X-API-Key header
      const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || API_BASE_URL;
      const url = `${API_BASE_URL}/usage/${serviceId}`;
      
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
      });

      // Parse response
      let data;
      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json")) {
        data = await response.json();
      } else {
        throw new Error("Invalid response format");
      }

      // Handle responses based on status code
      if (response.status === 200) {
        // Handle 200 - render usage data
        setUsageData(data);
        setError(null);
        toast.success("Usage data loaded successfully");
      } else if (response.status === 401) {
        // Handle 401 → "Invalid API key"
        const errorMsg = "Invalid API key";
        setError(errorMsg);
        setUsageData(null);
        toast.error(errorMsg);
      } else if (response.status === 404) {
        // Handle 404 → "Service not found"
        const errorMsg = "Service not found";
        setError(errorMsg);
        setUsageData(null);
        toast.error(errorMsg);
      } else {
        // Handle other HTTP errors
        const errorMessage = data?.detail || `HTTP error! status: ${response.status}`;
        setError(errorMessage);
        setUsageData(null);
        toast.error(errorMessage);
      }
    } catch (err) {
      setUsageData(null);
      
      // Handle network or other errors
      if (err instanceof TypeError) {
        const errorMessage = "Network error: Unable to reach the API server";
        setError(errorMessage);
        toast.error(errorMessage);
      } else {
        const errorMessage = err instanceof Error ? err.message : "An error occurred";
        setError(errorMessage);
        toast.error(errorMessage);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const totalRequests = usageData?.total_requests || 0;
  const maxRequests = usageData?.requests_by_api_key.reduce(
    (max, item) => Math.max(max, item.count),
    0
  ) || 0;

  return (
    <DashboardLayout>
      <div className="space-y-8">
        {/* Header */}
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">Usage Analytics</h1>
          <p className="text-muted-foreground text-sm">
            View request statistics and API key usage
          </p>
        </div>

        {/* Service ID or Gateway URL Input */}
        <Card className="border-border/50 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="text-base">Select Service</CardTitle>
            <CardDescription className="text-xs">
              Enter a Service ID or Gateway URL to view usage statistics
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {/* Service ID Input */}
              <div className="space-y-2">
                <Label htmlFor="serviceInput" className="text-sm font-medium">
                  Service ID or Gateway URL
                </Label>
                <Input
                  id="serviceInput"
                  type="text"
                  placeholder="2 or /proxy/2 or ${API_BASE_URL}/proxy/2"
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    // Clear error when user starts typing
                    if (error) setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !isLoading && input.trim()) {
                      fetchUsageData();
                    }
                  }}
                  disabled={isLoading}
                  className="bg-background font-mono text-sm"
                />
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <p className="font-medium">Accepted input formats:</p>
                  <ul className="list-disc list-inside space-y-0.5 ml-1">
                    <li>Service ID: <code className="bg-muted px-1 rounded">2</code></li>
                    <li>Gateway URL: <code className="bg-muted px-1 rounded">/proxy/2</code></li>
                    <li>Full URL: <code className="bg-muted px-1 rounded">{API_BASE_URL}/proxy/2</code></li>
                  </ul>
                </div>
              </div>

              {/* API Key Input */}
              <div className="space-y-2">
                <Label htmlFor="apiKeyInput" className="text-sm font-medium">
                  API Key
                </Label>
                <Input
                  id="apiKeyInput"
                  type="password"
                  placeholder="Paste your API key"
                  value={apiKeyInput}
                  onChange={(e) => {
                    setApiKeyInput(e.target.value);
                    // Clear error when user starts typing
                    if (error) setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !isLoading && input.trim() && apiKeyInput.trim()) {
                      fetchUsageData();
                    }
                  }}
                  disabled={isLoading}
                  className="bg-background font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Your API key is used only to authenticate requests to the gateway
                </p>
                
                {/* Remember Key Checkbox */}
                <div className="flex items-center space-x-2 pt-1">
                  <input
                    type="checkbox"
                    id="rememberKey"
                    checked={rememberKey}
                    onChange={(e) => setRememberKey(e.target.checked)}
                    disabled={isLoading}
                    className="h-4 w-4 rounded border-border text-primary focus:ring-primary focus:ring-offset-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  />
                  <Label 
                    htmlFor="rememberKey" 
                    className="text-sm font-normal cursor-pointer text-muted-foreground"
                  >
                    Remember this key
                  </Label>
                </div>
              </div>

              {/* Submit Button */}
              <div>
                <Button
                  onClick={fetchUsageData}
                  disabled={isLoading || !input.trim() || !apiKeyInput.trim()}
                  className="w-full transition-all hover:shadow-md"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Loading...
                    </>
                  ) : (
                    <>
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Fetch Usage
                    </>
                  )}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Error State */}
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Loading State */}
        {isLoading && (
          <div className="grid gap-6 md:grid-cols-2">
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-3 w-24 mt-2" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-24" />
                <Skeleton className="h-3 w-32 mt-2" />
              </CardContent>
            </Card>
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-3 w-24 mt-2" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          </div>
        )}

        {/* Usage Statistics */}
        {usageData && !isLoading && (
          <div className="grid gap-6 md:grid-cols-2">
            {/* Total Requests Card */}
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base">Total Requests</CardTitle>
                    <CardDescription className="text-xs">
                      All time statistics
                    </CardDescription>
                  </div>
                  <div className="h-10 w-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                    <Activity className="h-5 w-5 text-blue-500" />
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="text-3xl font-semibold tracking-tight">
                    {totalRequests.toLocaleString()}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Total requests processed
                  </p>
                  <div className="pt-2 flex items-center gap-2 text-xs text-muted-foreground">
                    <TrendingUp className="h-3.5 w-3.5" />
                    <span>Across {usageData.requests_by_api_key.length} API key{usageData.requests_by_api_key.length !== 1 ? 's' : ''}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Summary Card */}
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base">Statistics</CardTitle>
                    <CardDescription className="text-xs">
                      Usage breakdown
                    </CardDescription>
                  </div>
                  <div className="h-10 w-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                    <BarChart3 className="h-5 w-5 text-purple-500" />
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Active API Keys</span>
                    <span className="text-sm font-medium">
                      {usageData.requests_by_api_key.length}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Average per Key</span>
                    <span className="text-sm font-medium">
                      {usageData.requests_by_api_key.length > 0
                        ? Math.round(totalRequests / usageData.requests_by_api_key.length).toLocaleString()
                        : 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Highest Usage</span>
                    <span className="text-sm font-medium">
                      {maxRequests.toLocaleString()}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Requests by API Key Table */}
        {usageData && !isLoading && usageData.requests_by_api_key.length > 0 && (
          <Card className="border-border/50 bg-card/50 backdrop-blur">
            <CardHeader>
              <CardTitle className="text-base">Requests by API Key</CardTitle>
              <CardDescription className="text-xs">
                Breakdown of requests per API key
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">#</TableHead>
                      <TableHead>API Key</TableHead>
                      <TableHead className="text-right">Requests</TableHead>
                      <TableHead className="text-right">Percentage</TableHead>
                      <TableHead className="w-32">Usage</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {usageData.requests_by_api_key.map((item, index) => {
                      const percentage = totalRequests > 0
                        ? ((item.count / totalRequests) * 100).toFixed(1)
                        : "0.0";
                      const barWidth = maxRequests > 0
                        ? (item.count / maxRequests) * 100
                        : 0;

                      return (
                        <TableRow key={item.api_key}>
                          <TableCell className="text-muted-foreground">
                            {index + 1}
                          </TableCell>
                          <TableCell>
                            <code className="text-xs font-mono bg-muted px-2 py-1 rounded">
                              {item.api_key.substring(0, 24)}...
                            </code>
                          </TableCell>
                          <TableCell className="text-right font-medium">
                            {item.count.toLocaleString()}
                          </TableCell>
                          <TableCell className="text-right text-muted-foreground">
                            {percentage}%
                          </TableCell>
                          <TableCell>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="h-2 rounded-full bg-primary transition-all"
                                style={{ width: `${barWidth}%` }}
                              />
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Empty State - Show when no API keys or no requests */}
        {usageData && !isLoading && (usageData.requests_by_api_key.length === 0 || usageData.total_requests === 0) && (
          <Card className="border-border/50 bg-card/50 backdrop-blur">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <BarChart3 className="h-12 w-12 text-muted-foreground mb-4 opacity-50" />
              <p className="text-sm font-medium mb-1">No usage data</p>
              <p className="text-xs text-muted-foreground text-center max-w-md">
                {usageData.total_requests === 0
                  ? "This service hasn't processed any requests yet. Make requests through the gateway to see analytics."
                  : "No API keys have made requests to this service yet."}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Initial State */}
        {!usageData && !isLoading && !error && (
          <Card className="border-border/50 bg-card/50 backdrop-blur">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <BarChart3 className="h-12 w-12 text-muted-foreground mb-4 opacity-50" />
              <p className="text-sm font-medium mb-1">No data loaded</p>
              <p className="text-xs text-muted-foreground text-center">
                Enter a service ID and click "Fetch Usage" to view statistics
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}
