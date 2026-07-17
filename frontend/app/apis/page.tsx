import { API_BASE_URL } from "@/lib/api";
"use client";

import { useState } from "react";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "@/components/ui/toaster";
import { api, setApiKey } from "@/lib/api";
import {
  Code,
  CheckCircle2,
  Copy,
  ExternalLink,
  Info,
  Loader2,
  Sparkles
} from "lucide-react";

interface RegistrationResponse {
  service_id: number;
  gateway_url: string;
  api_key?: string;
}

export default function APIsPage() {
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<RegistrationResponse | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Preset APIs for quick registration
  const presetApis = [
    { name: "JSONPlaceholder", url: "https://jsonplaceholder.typicode.com", description: "Fake REST API for testing" },
    { name: "ReqRes", url: "https://reqres.in/api", description: "Fake user data API" },
    { name: "Dog CEO", url: "https://dog.ceo/api", description: "Random dog images" },
    { name: "Cat Facts", url: "https://catfact.ninja", description: "Random cat facts" },
    { name: "Open Meteo", url: "https://api.open-meteo.com/v1", description: "Free weather API" },
    { name: "PokéAPI", url: "https://pokeapi.co/api/v2", description: "Pokémon data" },
  ];

  const selectPreset = (preset: { name: string; url: string }) => {
    setName(preset.name);
    setTargetUrl(preset.url);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const data = await api.registerApi(name, targetUrl);
      setSuccess(data);
      setName("");
      setTargetUrl("");
      
      // Save API key to localStorage if provided
      if (data.api_key) {
        setApiKey(data.api_key);
      }
      
      toast.success("API registered successfully!");
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "An error occurred";
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    toast.success(`${field === "gateway" ? "Gateway URL" : "API key"} copied to clipboard`);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        {/* Header */}
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">Register API</h1>
          <p className="text-muted-foreground text-sm">
            Connect your backend service to the gateway
          </p>
        </div>

        {/* Success State */}
        {success && (
          <Alert className="border-green-500/50 bg-green-500/5">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <AlertDescription className="text-green-600 dark:text-green-400">
              API registered successfully! Your service is now available through the gateway.
            </AlertDescription>
          </Alert>
        )}

        {/* Error State */}
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Registration Form */}
          <div className="lg:col-span-2">
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Sparkles className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle>Service Details</CardTitle>
                    <CardDescription className="text-xs">
                      Provide information about your backend service
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Quick Select Presets */}
                  <div className="space-y-2">
                    <Label className="text-sm font-medium">Quick Select</Label>
                    <div className="flex flex-wrap gap-2">
                      {presetApis.map((preset) => (
                        <Button
                          key={preset.url}
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => selectPreset(preset)}
                          className="text-xs"
                        >
                          {preset.name}
                        </Button>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Click a preset to auto-fill, or enter custom details below
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="name" className="text-sm font-medium">
                      API Name
                    </Label>
                    <Input
                      id="name"
                      placeholder="My Awesome API"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      required
                      disabled={isLoading}
                      className="bg-background"
                    />
                    <p className="text-xs text-muted-foreground">
                      A friendly name to identify your service
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="targetUrl" className="text-sm font-medium">
                      Target URL
                    </Label>
                    <Input
                      id="targetUrl"
                      type="url"
                      placeholder="https://api.example.com"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      required
                      disabled={isLoading}
                      className="bg-background"
                    />
                    <p className="text-xs text-muted-foreground">
                      The base URL of your backend service (must include http:// or https://)
                    </p>
                  </div>

                  <Button
                    type="submit"
                    className="w-full transition-all hover:shadow-md"
                    disabled={isLoading || !name || !targetUrl}
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Registering...
                      </>
                    ) : (
                      <>
                        <Code className="mr-2 h-4 w-4" />
                        Register API
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Info Card */}
          <div className="space-y-4">
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <CardTitle className="text-sm">How it works</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-muted-foreground">
                <div className="space-y-1">
                  <p className="font-medium text-foreground">1. Register your service</p>
                  <p className="text-xs">
                    Provide your backend URL and we'll create a gateway endpoint
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="font-medium text-foreground">2. Get your gateway URL</p>
                  <p className="text-xs">
                    Use the generated endpoint to route requests through our gateway
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="font-medium text-foreground">3. Secure with API key</p>
                  <p className="text-xs">
                    Authenticate requests using your unique API key
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Success Details */}
        {success && (
          <div className="space-y-4">
            <Card className="border-green-500/20 bg-green-500/5">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <CardTitle>Registration Complete</CardTitle>
                </div>
                <CardDescription>
                  Your API has been registered. Save these details securely.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Gateway URL */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium text-muted-foreground">
                    Gateway URL
                  </Label>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 rounded-md border border-border bg-background px-3 py-2 font-mono text-sm">
                      {`${API_BASE_URL}${success.gateway_url}`}
                    </div>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(`${API_BASE_URL}${success.gateway_url}`, "gateway")}
                      className="shrink-0 transition-all hover:scale-105"
                    >
                      {copiedField === "gateway" ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Use this URL to make requests through the gateway
                  </p>
                </div>

                {/* API Key */}
                {success.api_key && (
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-muted-foreground">
                      API Key
                      <span className="ml-2 text-xs font-normal text-amber-500">
                        (shown once)
                      </span>
                    </Label>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 rounded-md border border-amber-500/50 bg-amber-500/5 px-3 py-2 font-mono text-sm">
                        {success.api_key}
                      </div>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => copyToClipboard(success.api_key!, "apikey")}
                        className="shrink-0 transition-all hover:scale-105"
                      >
                        {copiedField === "apikey" ? (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    <Alert className="border-amber-500/50 bg-amber-500/5">
                      <Info className="h-4 w-4 text-amber-500" />
                      <AlertDescription className="text-xs text-amber-600 dark:text-amber-400">
                        This API key will only be shown once. Make sure to save it securely. 
                        It has been automatically saved to your browser's local storage.
                      </AlertDescription>
                    </Alert>
                  </div>
                )}

                {/* Usage Example */}
                <div className="space-y-2 pt-2">
                  <Label className="text-sm font-medium text-muted-foreground">
                    Usage Example
                  </Label>
                  <div className="rounded-md border border-border bg-muted/30 p-3">
                    <code className="text-xs text-muted-foreground">
                      <div className="mb-1">curl ${API_BASE_URL}{success.gateway_url} \</div>
                      <div className="pl-4">-H "X-API-Key: {success.api_key?.substring(0, 20)}..."</div>
                    </code>
                  </div>
                </div>

                <div className="flex gap-2 pt-2">
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={() => {
                      setSuccess(null);
                      setError(null);
                    }}
                  >
                    Register Another API
                  </Button>
                  <Button
                    variant="default"
                    className="flex-1"
                    onClick={() => window.location.href = "/"}
                  >
                    Go to Dashboard
                    <ExternalLink className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
