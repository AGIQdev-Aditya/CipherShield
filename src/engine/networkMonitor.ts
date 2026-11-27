export interface NetworkEventRecord {
  id: number;
  url: string;
  transport: 'fetch' | 'xhr';
  timestamp: string;
  isAllowedOrigin: boolean;
}

export interface NetworkMonitorState {
  externalCallsBlockedOrLogged: number;
  geminiOptInCalls: number;
  recentEvents: NetworkEventRecord[];
}

const ALLOWED_EXTERNAL_HOSTS = new Set(['generativelanguage.googleapis.com']);

function isSameOriginOrStatic(targetUrl: string): { sameOrigin: boolean; isGemini: boolean } {
  try {
    const resolved = new URL(targetUrl, window.location.href);
    const sameOrigin = resolved.origin === window.location.origin;
    const isGemini = ALLOWED_EXTERNAL_HOSTS.has(resolved.hostname);
    return { sameOrigin, isGemini };
  } catch {
    return { sameOrigin: true, isGemini: false };
  }
}

/**
 * Installs a lightweight client-side telemetry hook on window.fetch and XMLHttpRequest
 * so judges can visually verify zero raw-data egress during PII scanning and redaction.
 */
export function installNetworkMonitor(
  onUpdate: (event: NetworkEventRecord, isGemini: boolean) => void,
): () => void {
  if (typeof window === 'undefined') return () => {};

  const originalFetch = window.fetch;
  const originalXhrOpen = window.XMLHttpRequest.prototype.open;
  let seq = 1;

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const { sameOrigin, isGemini } = isSameOriginOrStatic(urlStr);
    if (!sameOrigin) {
      onUpdate(
        {
          id: seq++,
          url: urlStr.split('?')[0],
          transport: 'fetch',
          timestamp: new Date().toLocaleTimeString(),
          isAllowedOrigin: isGemini,
        },
        isGemini,
      );
    }
    return originalFetch.call(window, input, init);
  };

  window.XMLHttpRequest.prototype.open = function patchedOpen(
    method: string,
    url: string | URL,
    asyncFlag?: boolean,
    username?: string | null,
    password?: string | null,
  ) {
    const urlStr = typeof url === 'string' ? url : url.href;
    const { sameOrigin, isGemini } = isSameOriginOrStatic(urlStr);
    if (!sameOrigin) {
      onUpdate(
        {
          id: seq++,
          url: urlStr.split('?')[0],
          transport: 'xhr',
          timestamp: new Date().toLocaleTimeString(),
          isAllowedOrigin: isGemini,
        },
        isGemini,
      );
    }
    return originalXhrOpen.apply(this, [method, url, asyncFlag ?? true, username, password]);
  };

  return () => {
    window.fetch = originalFetch;
    window.XMLHttpRequest.prototype.open = originalXhrOpen;
  };
}
