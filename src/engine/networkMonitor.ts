export interface NetworkEventRecord {
  id: number;
  url: string;
  transport: 'fetch' | 'xhr' | 'beacon' | 'resource';
  timestamp: string;
  isAllowedOrigin: boolean;
}

export interface NetworkMonitorState {
  externalCallsBlockedOrLogged: number;
  geminiOptInCalls: number;
  recentEvents: NetworkEventRecord[];
}

const ALLOWED_EXTERNAL_HOSTS = new Set(['generativelanguage.googleapis.com']);

function inspectOrigin(targetUrl: string): { sameOrigin: boolean; isGemini: boolean } {
  try {
    const resolved = new URL(targetUrl, window.location.href);
    const sameOrigin = resolved.origin === window.location.origin || resolved.protocol === 'blob:' || resolved.protocol === 'data:';
    const isGemini = ALLOWED_EXTERNAL_HOSTS.has(resolved.hostname);
    return { sameOrigin, isGemini };
  } catch {
    return { sameOrigin: true, isGemini: false };
  }
}

/**
 * Installs client-side runtime network activity monitoring over fetch, XMLHttpRequest,
 * navigator.sendBeacon, and PerformanceObserver resource entries.
 */
export function installNetworkMonitor(
  onUpdate: (event: NetworkEventRecord, isGemini: boolean) => void,
): () => void {
  if (typeof window === 'undefined') return () => {};

  const originalFetch = window.fetch;
  const originalXhrOpen = window.XMLHttpRequest.prototype.open;
  const originalSendBeacon = typeof navigator !== 'undefined' && navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
  let seq = 1;

  const recordIfExternal = (urlStr: string, transport: NetworkEventRecord['transport']) => {
    const { sameOrigin, isGemini } = inspectOrigin(urlStr);
    if (!sameOrigin) {
      onUpdate(
        {
          id: seq++,
          url: urlStr.split('?')[0] ?? urlStr,
          transport,
          timestamp: new Date().toLocaleTimeString(),
          isAllowedOrigin: isGemini,
        },
        isGemini,
      );
    }
  };

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    recordIfExternal(urlStr, 'fetch');
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
    recordIfExternal(urlStr, 'xhr');
    return originalXhrOpen.apply(this, [method, url, asyncFlag ?? true, username, password]);
  };

  if (originalSendBeacon) {
    navigator.sendBeacon = (url: string | URL, data?: BodyInit | null) => {
      recordIfExternal(typeof url === 'string' ? url : url.href, 'beacon');
      return originalSendBeacon(url, data);
    };
  }

  let perfObserver: PerformanceObserver | null = null;
  if (typeof PerformanceObserver !== 'undefined') {
    try {
      perfObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.name) {
            recordIfExternal(entry.name, 'resource');
          }
        }
      });
      perfObserver.observe({ type: 'resource', buffered: true });
    } catch {
      perfObserver = null;
    }
  }

  return () => {
    window.fetch = originalFetch;
    window.XMLHttpRequest.prototype.open = originalXhrOpen;
    if (originalSendBeacon) {
      navigator.sendBeacon = originalSendBeacon;
    }
    perfObserver?.disconnect();
  };
}
