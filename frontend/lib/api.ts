/**
 * API client for communicating with the FastAPI backend
 */

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "https://aegis-gateway-k583.onrender.com";

export interface ApiError {
  detail: string;
}

export class ApiRequestError extends Error {
  statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = "ApiRequestError";
    this.statusCode = statusCode;
  }
}

/**
 * Storage key for API key in localStorage
 */
const API_KEY_STORAGE_KEY = "api_key";

/**
 * Get API key from localStorage securely.
 * 
 * Returns the stored API key or null if not found.
 * This function safely handles server-side rendering (SSR) by checking for window.
 * The API key is never exposed in the UI unless explicitly requested.
 * 
 * @returns The API key string or null if not available
 * 
 * @example
 * ```ts
 * const apiKey = getApiKey();
 * if (apiKey) {
 *   // Use the API key
 * }
 * ```
 */
export function getApiKey(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem(API_KEY_STORAGE_KEY);
  } catch (error) {
    // localStorage may not be available (e.g., in private browsing mode)
    console.error("Failed to retrieve API key from localStorage:", error);
    return null;
  }
}

/**
 * Save API key to localStorage securely.
 * 
 * Stores the API key in browser localStorage for future use.
 * The key is stored securely and is only accessible via getApiKey().
 * This is automatically called after API registration.
 * 
 * @param apiKey - The API key to store
 * 
 * @example
 * ```ts
 * setApiKey("your-api-key-here");
 * ```
 */
export function setApiKey(apiKey: string): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(API_KEY_STORAGE_KEY, apiKey);
  } catch (error) {
    // localStorage may not be available (e.g., in private browsing mode)
    console.error("Failed to save API key to localStorage:", error);
    throw new Error("Failed to save API key. Please check your browser settings.");
  }
}

/**
 * Remove API key from localStorage.
 * 
 * Clears the stored API key from browser localStorage.
 * 
 * @example
 * ```ts
 * removeApiKey();
 * ```
 */
export function removeApiKey(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(API_KEY_STORAGE_KEY);
  } catch (error) {
    console.error("Failed to remove API key from localStorage:", error);
  }
}

/**
 * Make an API request with automatic API key handling
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const apiKey = getApiKey();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> || {}),
  };

  // Add API key to headers if available
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  const url = `${API_BASE_URL}${endpoint}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    // Handle non-JSON responses
    const contentType = response.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
      if (!response.ok) {
        throw new ApiRequestError(
          `HTTP error! status: ${response.status}`,
          response.status
        );
      }
      return {} as T;
    }

    const data = await response.json();

    if (!response.ok) {
      const error: ApiError = data;
      throw new ApiRequestError(
        error.detail || `HTTP error! status: ${response.status}`,
        response.status
      );
    }

    return data as T;
  } catch (error) {
    // If it's already an ApiRequestError, re-throw it
    if (error instanceof ApiRequestError) {
      throw error;
    }
    // Handle network errors
    if (error instanceof TypeError) {
      throw new Error("Network error: Unable to reach the API server");
    }
    throw error;
  }
}

/**
 * API client methods
 */
export const api = {
  /**
   * Register a new API service
   */
  registerApi: async (name: string, targetUrl: string) => {
    return apiRequest<{
      service_id: number;
      gateway_url: string;
      api_key?: string;
    }>("/register-api", {
      method: "POST",
      body: JSON.stringify({ name, target_url: targetUrl }),
    });
  },

  /**
   * Get usage statistics for a service
   */
  getUsage: async (serviceId: number) => {
    return apiRequest<{
      service_id: number;
      total_requests: number;
      requests_by_api_key: Array<{
        api_key: string;
        count: number;
      }>;
    }>(`/usage/${serviceId}`);
  },

  /**
   * Get the user's API key (demo endpoint)
   */
  getMyApiKey: async () => {
    return apiRequest<{
      api_key?: string;
      message?: string;
    }>("/me/api-key");
  },

  /**
   * Health check
   */
  healthCheck: async () => {
    return apiRequest<{ status: string }>("/health");
  },

  /**
   * Get overview statistics
   */
  getOverview: async () => {
    return apiRequest<{
      total_services: number;
      requests_today: number;
      top_services: Array<{
        name: string;
        request_count: number;
      }>;
      average_rate_limit_usage: number;
      gateway_status: string;
    }>("/overview");
  },

  /**
   * List all API keys for all services
   */
  listAllApiKeys: async () => {
    return apiRequest<{
      services: Array<{
        service_id: number;
        service_name: string;
        api_keys: Array<{
          id: number;
          key_masked: string;
          created_at: string | null;
          is_active: boolean;
        }>;
      }>;
    }>("/api-keys");
  },

  /**
   * Revoke an API key
   */
  revokeApiKey: async (serviceId: number, keyId: number) => {
    return apiRequest<{
      message: string;
      key_id: number;
      service_id: number;
    }>(`/services/${serviceId}/keys/${keyId}/revoke`, {
      method: "PATCH",
    });
  },

  /**
   * Create a new API key for a service
   */
  createServiceApiKey: async (serviceId: number) => {
    return apiRequest<{
      api_key: string;
      service_id: number;
      message: string;
    }>(`/services/${serviceId}/keys`, {
      method: "POST",
    });
  },

  /**
   * Update rate limits for a specific API key
   */
  updateApiKeyRateLimit: async (keyId: number, requests: number, windowSeconds: number) => {
    return apiRequest<{
      message: string;
      key_id: number;
      rate_limit_requests: number;
      rate_limit_window_seconds: number;
    }>(`/api-keys/${keyId}/rate-limit`, {
      method: "PUT",
      body: JSON.stringify({
        requests,
        window_seconds: windowSeconds,
      }),
    });
  },

  /**
   * Get billing summary overview
   */
  getBillingSummary: async () => {
    return apiRequest<{
      total_requests: number;
      total_cost: number;
      cost_this_month: number;
    }>("/billing/summary");
  },

  /**
   * Get billing information for all API keys
   */
  getBillingApiKeys: async () => {
    return apiRequest<{
      api_keys: Array<{
        api_key_id: number;
        service_name: string;
        requests_used: number;
        price_per_request: number;
        total_cost: number;
      }>;
    }>("/billing/api-keys");
  },

  /**
   * Reset billing cycle (reset all API key costs)
   */
  resetBilling: async () => {
    return apiRequest<{
      message: string;
      reset_count: number;
    }>("/billing/reset", {
      method: "POST",
    });
  },

  /**
   * Update price per request for a specific API key
   */
  updateApiKeyPrice: async (keyId: number, pricePerRequest: number) => {
    return apiRequest<{
      id: number;
      key: string;
      service_id: number;
      is_active: boolean;
      created_at: string | null;
      rate_limit_requests: number | null;
      rate_limit_window_seconds: number | null;
      price_per_request: number;
      total_cost: number;
    }>(`/api-keys/${keyId}/pricing`, {
      method: "PUT",
      body: JSON.stringify({
        price_per_request: pricePerRequest,
      }),
    });
  },

  // ============================================================================
  // Bot Detection & Security
  // ============================================================================

  /**
   * Get bot activity data
   */
  getBotActivity: async () => {
    return apiRequest<{
      total_requests: number;
      bot_percentage: number;
      blocked_count: number;
      suspicious_count: number;
      recent_activity: Array<{
        id: number;
        timestamp: string | null;
        service_id: number;
        service_name: string;
        api_key: string;
        bot_score: number;
        classification: string;
        user_agent: string;
        action_taken: string;
      }>;
    }>("/security/bot-activity");
  },

  /**
   * Get bot statistics
   */
  getBotStats: async () => {
    return apiRequest<{
      classification_breakdown: {
        human: number;
        suspicious: number;
        bot: number;
      };
      top_bot_user_agents: Array<{
        user_agent: string;
        count: number;
      }>;
    }>("/security/bot-stats");
  },

  /**
   * Update bot blocking configuration for a service
   */
  updateBotBlocking: async (serviceId: number, enabled: boolean) => {
    return apiRequest<{
      message: string;
      service_id: number;
      block_bots_enabled: boolean;
    }>(`/services/${serviceId}/bot-blocking`, {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    });
  },

  /**
   * Get all bot blocking configurations
   */
  getAllBotBlockingConfigs: async () => {
    return apiRequest<{
      services: Array<{
        service_id: number;
        service_name: string;
        block_bots_enabled: boolean;
      }>;
    }>("/services/bot-blocking");
  },

  // ============================================================================
  // Watermarking / Data Protection
  // ============================================================================

  /**
   * Get list of all services with watermarking status
   */
  listServices: async () => {
    return apiRequest<{
      services: Array<{
        id: number;
        name: string;
        target_url: string;
        watermarking_enabled: boolean;
      }>;
    }>("/services/list");
  },

  /**
   * Get watermarking status for a specific service
   */
  getWatermarkingStatus: async (serviceId: number) => {
    return apiRequest<{
      service_id: number;
      service_name: string;
      watermarking_enabled: boolean;
    }>(`/services/${serviceId}/watermarking`);
  },

  /**
   * Toggle watermarking for a service
   */
  toggleWatermarking: async (serviceId: number, enabled: boolean) => {
    return apiRequest<{
      message: string;
      service_id: number;
      service_name: string;
      watermarking_enabled: boolean;
    }>(`/services/${serviceId}/watermarking`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  },

  /**
   * Verify leaked data and extract watermark
   */
  verifyWatermark: async (data: string) => {
    return apiRequest<{
      watermark_found: boolean;
      raw_watermark: string;
      decoded: {
        service_id: number;
        service_name: string;
        api_key_id: number;
        api_key_masked: string;
        request_id: string;
        timestamp: string;
      };
      attribution: string;
    }>("/watermark/verify", {
      method: "POST",
      body: JSON.stringify({ data }),
    });
  },

  /**
   * Delete a service and all its related data
   */
  deleteService: async (serviceId: number) => {
    return apiRequest<{
      message: string;
      service_id: number;
      service_name: string;
    }>(`/services/${serviceId}`, {
      method: "DELETE",
    });
  },

  // ============================================================================
  // Cryptographic Transparency (Merkle Trees)
  // ============================================================================

  /**
   * Get the latest Merkle root
   */
  getMerkleLatest: async () => {
    return apiRequest<{
      batch_id: number;
      merkle_root: string;
      start_time: string;
      end_time: string;
      request_count: number;
      created_at: string;
    }>("/transparency/merkle-latest");
  },

  /**
   * Get historical Merkle roots with pagination
   */
  getMerkleHistory: async (limit: number = 50, offset: number = 0) => {
    return apiRequest<{
      merkle_roots: Array<{
        batch_id: number;
        merkle_root: string;
        start_time: string;
        end_time: string;
        request_count: number;
        created_at: string;
      }>;
      total: number;
      limit: number;
      offset: number;
    }>(`/transparency/merkle-history?limit=${limit}&offset=${offset}`);
  },

  /**
   * Get hashes for a Merkle batch for client-side verification
   */
  verifyMerkleBatch: async (batchId: number) => {
    return apiRequest<{
      batch_id: number;
      hashes: string[];
      expected_root: string;
      request_count: number;
      start_time: string;
      end_time: string;
    }>(`/transparency/verify/${batchId}`);
  },

  /**
   * Get blockchain anchoring proof for a Merkle batch
   */
  getBlockchainProof: async (batchId: number) => {
    return apiRequest<{
      batch_id: number;
      is_anchored: boolean;
      tx_hash?: string;
      block_number?: number;
      anchored_at?: string;
      etherscan_url?: string;
      message?: string;
    }>(`/transparency/blockchain/${batchId}`);
  },

  // --- Adaptive Anomaly Detection (Feature A) ---

  /**
   * Health of the anomaly detection subsystem (worker liveness, degraded mode,
   * active thresholds and fusion weights).
   */
  getAnomalyStatus: async () => {
    return apiRequest<{
      worker_alive: boolean;
      degraded_mode: boolean;
      mode: string;
      thresholds: { log: number; tarpit: number; block: number };
      weights: { global: number; per_key: number; enumeration: number; auth_abuse: number };
    }>("/security/anomaly/status");
  },

  /**
   * Recent elevated risk decisions (risk >= log threshold), newest first.
   */
  getAnomalyScores: async (limit = 50) => {
    return apiRequest<{
      count: number;
      scores: Array<{
        id: number;
        api_key_id: number;
        service_id: number;
        risk: number;
        action: string;
        endpoint: string | null;
        sub_scores: {
          global: number;
          per_key: number;
          enumeration: number;
          auth_abuse: number;
        };
        timestamp: string | null;
      }>;
    }>(`/security/anomaly/scores?limit=${limit}`);
  },

  /**
   * Live cached risk decision for a single API key.
   */
  getAnomalyRisk: async (apiKeyId: number) => {
    return apiRequest<{
      api_key_id: number;
      action: string;
      risk: number | null;
      scored: boolean;
    }>(`/security/anomaly/risk/${apiKeyId}`);
  },

  /**
   * Live traffic totals (allowed vs flagged) + last real-traffic replay summary.
   */
  getAnomalyOverview: async () => {
    return apiRequest<{
      processed: number;
      allowed: number;
      logged: number;
      tarpitted: number;
      blocked: number;
      flagged: number;
      allowed_pct: number;
      flagged_pct: number;
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
        real_flagged_samples: Array<{
          api_key_id: number;
          endpoint: string;
          action: string;
          risk: number;
        }>;
      } | null;
    }>("/security/anomaly/overview");
  },

  /**
   * Replay REAL HTTP traffic (NASA-HTTP) through the live scorer in the
   * background. Returns immediately; watch the overview/table fill in.
   */
  replayRealTraffic: async (events = 4000, injectAttack = true) => {
    return apiRequest<{ status: string; events: number; message: string }>(
      "/security/anomaly/replay",
      { method: "POST", body: JSON.stringify({ events, inject_attack: injectAttack }) }
    );
  },

  /**
   * Drive synthetic attack traffic through the live scoring pipeline (demo).
   * scenario: "credential_stuffing" | "enumeration" | "low_and_slow" | "all".
   */
  simulateAnomalyAttack: async (scenario = "all") => {
    return apiRequest<{
      message: string;
      scenarios_run: number;
      results: Array<{
        scenario: string;
        demo_key_id: number;
        warmup_events: number;
        attack_events: number;
        flagged: number;
        blocked: number;
        tarpitted: number;
        recall: number;
        peak_risk: number;
        first_detection_after: number | null;
        final_action: string;
      }>;
    }>("/security/anomaly/simulate", {
      method: "POST",
      body: JSON.stringify({ scenario }),
    });
  },
};
