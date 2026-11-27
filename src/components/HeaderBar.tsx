import { FileText, Lock, Moon, ShieldAlert, ShieldCheck, Sun } from 'lucide-react';
import { NetworkMonitorState } from '../engine/networkMonitor';

interface HeaderBarProps {
  theme: 'system' | 'dark' | 'light';
  networkState: NetworkMonitorState;
  onCycleTheme: () => void;
  onOpenPromptLog: () => void;
}

/**
 * Top landmark header with live Zero-Egress network telemetry badge, Prompt Log trigger, and theme switcher.
 */
export function HeaderBar({ theme, networkState, onCycleTheme, onOpenPromptLog }: HeaderBarProps) {
  const hasUnexpectedCall = networkState.externalCallsBlockedOrLogged > 0;

  return (
    <header className="site-header">
      <div className="brand-group">
        <div className="brand-mark" aria-hidden="true">
          <ShieldCheck size={22} />
        </div>
        <div>
          <h1 id="main-heading" tabIndex={-1} className="brand-title">
            CipherShield
          </h1>
          <p className="brand-subtitle">
            Zero-Egress Client-Side PII Detection, Luhn/Verhoeff Validation &amp; Audit Studio
          </p>
        </div>
      </div>

      <nav aria-label="Primary actions" className="header-actions">
        <span
          className={`status-pill ${hasUnexpectedCall ? 'status-pill-warn' : ''}`}
          title="Runtime fetch, XHR, sendBeacon, and Resource Performance monitor tracks external requests"
        >
          {hasUnexpectedCall ? <ShieldAlert size={14} aria-hidden="true" /> : <Lock size={14} aria-hidden="true" />}
          {hasUnexpectedCall
            ? `External Calls: ${networkState.externalCallsBlockedOrLogged}`
            : `Network Monitor · 0 External Calls`}
          {networkState.geminiOptInCalls > 0 ? ` (${networkState.geminiOptInCalls} Gemini)` : ''}
        </span>

        <button type="button" className="btn" onClick={onOpenPromptLog}>
          <FileText size={16} aria-hidden="true" />
          Prompt Log
        </button>

        <button
          type="button"
          className="btn"
          onClick={onCycleTheme}
          aria-label={`Switch color theme, current setting is ${theme}`}
        >
          {theme === 'light' ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
          Theme: {theme}
        </button>
      </nav>
    </header>
  );
}
