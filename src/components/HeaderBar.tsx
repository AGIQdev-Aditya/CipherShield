import { FileText, Lock, Moon, ShieldCheck, Sun } from 'lucide-react';

interface HeaderBarProps {
  theme: 'system' | 'dark' | 'light';
  onCycleTheme: () => void;
  onOpenPromptLog: () => void;
}

/**
 * Top landmark header with client-side security badge, Prompt Log modal trigger, and theme switcher.
 */
export function HeaderBar({ theme, onCycleTheme, onOpenPromptLog }: HeaderBarProps) {
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
        <span className="status-pill" title="Enforced by CSP connect-src 'self' and pure local JS">
          <Lock size={14} aria-hidden="true" />
          100% Client-Side · 0 Network Egress
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
