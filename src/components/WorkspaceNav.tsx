import React, { useLayoutEffect, useRef } from 'react';
import { FlaskConical, KeyRound, ShieldCheck, Sparkles } from 'lucide-react';
import { NetworkMonitorState } from '../engine/networkMonitor';

export type WorkspaceTab = 'studio' | 'vault' | 'proof' | 'gemini';

export const WORKSPACE_TABS: { id: WorkspaceTab; label: string; shortcut: string }[] = [
  { id: 'studio', label: 'Sanitize Studio', shortcut: '1' },
  { id: 'vault', label: 'Entity Review & Vault', shortcut: '2' },
  { id: 'proof', label: 'Self-Test & Proof', shortcut: '3' },
  { id: 'gemini', label: 'Compliance Advisor', shortcut: '4' },
];

interface WorkspaceNavProps {
  activeTab: WorkspaceTab;
  detectedCount: number;
  mappingCount: number;
  selfTestSummary: string | null;
  showProofLog: boolean;
  shouldUseWorker: boolean;
  networkState: NetworkMonitorState;
  onSelectTab: (tab: WorkspaceTab) => void;
  onToggleProofLog: () => void;
}

function getTabIcon(id: WorkspaceTab) {
  if (id === 'studio') return <ShieldCheck size={16} aria-hidden="true" />;
  if (id === 'vault') return <KeyRound size={16} aria-hidden="true" />;
  if (id === 'proof') return <FlaskConical size={16} aria-hidden="true" />;
  return <Sparkles size={16} aria-hidden="true" />;
}

function NetworkProofDrawer({
  networkState,
  shouldUseWorker,
}: {
  networkState: NetworkMonitorState;
  shouldUseWorker: boolean;
}) {
  return (
    <div className="proof-log" id="proof-log" role="region" aria-label="Intercepted network events">
      {networkState.recentEvents.length === 0 ? (
        <p className="muted-copy proof-empty">
          Zero external requests intercepted across fetch, XHR, sendBeacon, and Resource observers. Scanning, CSV
          redaction, and PBKDF2 600k + AES-256-GCM vault operations executed strictly in{' '}
          {shouldUseWorker ? 'Web Worker + local RAM' : 'local browser RAM'}.
        </p>
      ) : (
        <ul className="proof-events">
          {networkState.recentEvents.map((ev) => (
            <li key={ev.id}>
              <span className="mono">{ev.timestamp}</span>
              <span className={ev.isAllowedOrigin ? 'log-optin' : 'log-unexpected'}>{ev.transport}</span>
              <span className="log-url mono">{ev.url}</span>
              <span>{ev.isAllowedOrigin ? 'opt-in' : 'unexpected'}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Sticky accessible tab bar with gliding indicator pill and expandable Zero-Egress network drawer.
 */
export function WorkspaceNav({
  activeTab,
  detectedCount,
  mappingCount,
  selfTestSummary,
  showProofLog,
  shouldUseWorker,
  networkState,
  onSelectTab,
  onToggleProofLog,
}: WorkspaceNavProps) {
  const navSliderRef = useRef<HTMLSpanElement>(null);
  const tabRefs = useRef<Record<WorkspaceTab, HTMLButtonElement | null>>({
    studio: null,
    vault: null,
    proof: null,
    gemini: null,
  });

  useLayoutEffect(() => {
    const updateSlider = () => {
      const activeBtn = tabRefs.current[activeTab];
      const slider = navSliderRef.current;
      if (!activeBtn || !slider) return;
      slider.style.width = `${activeBtn.offsetWidth}px`;
      slider.style.transform = `translate3d(${activeBtn.offsetLeft}px, ${activeBtn.offsetTop}px, 0)`;
    };
    updateSlider();
    window.addEventListener('resize', updateSlider);
    return () => window.removeEventListener('resize', updateSlider);
  }, [activeTab, detectedCount, mappingCount, selfTestSummary]);

  const getTabBadge = (id: WorkspaceTab): string | null => {
    if (id === 'studio' && detectedCount > 0) return String(detectedCount);
    if (id === 'vault' && mappingCount > 0) return String(mappingCount);
    if (id === 'proof' && selfTestSummary) return selfTestSummary;
    return null;
  };

  const onTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const nextIdx =
      e.key === 'Home'
        ? 0
        : e.key === 'End'
          ? WORKSPACE_TABS.length - 1
          : (idx + (e.key === 'ArrowRight' ? 1 : -1) + WORKSPACE_TABS.length) % WORKSPACE_TABS.length;
    const nextTab = WORKSPACE_TABS[nextIdx];
    if (!nextTab) return;
    onSelectTab(nextTab.id);
    tabRefs.current[nextTab.id]?.focus();
  };

  const egressClean = networkState.externalCallsBlockedOrLogged === 0;

  return (
    <>
      <nav className="workspace-nav-shell" aria-label="Workspace navigation">
        <div className="workspace-tabs" role="tablist" aria-label="CipherShield workspace sections">
          <span ref={navSliderRef} className="ws-slider" aria-hidden="true" />
          {WORKSPACE_TABS.map((tab, idx) => {
            const badge = getTabBadge(tab.id);
            const selected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                ref={(el) => {
                  tabRefs.current[tab.id] = el;
                }}
                type="button"
                role="tab"
                id={`ws-tab-${tab.id}`}
                aria-selected={selected}
                aria-controls={`ws-panel-${tab.id}`}
                tabIndex={selected ? 0 : -1}
                className={`ws-tab ${selected ? 'is-active' : ''}`}
                onClick={() => onSelectTab(tab.id)}
                onKeyDown={(e) => onTabKeyDown(e, idx)}
                title={`${tab.label} (Alt+${tab.shortcut})`}
              >
                {getTabIcon(tab.id)}
                <span>{tab.label}</span>
                {badge && <span className="drawer-count mono">{badge}</span>}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          className="btn btn-compact proof-pill-btn"
          aria-expanded={showProofLog}
          aria-controls="proof-log"
          onClick={onToggleProofLog}
        >
          <span className={`proof-dot ${egressClean ? '' : 'is-hot'}`} aria-hidden="true" />
          <span>{egressClean ? '0 External Egress' : `${networkState.externalCallsBlockedOrLogged} Calls`}</span>
        </button>
      </nav>

      {showProofLog && <NetworkProofDrawer networkState={networkState} shouldUseWorker={shouldUseWorker} />}
    </>
  );
}
