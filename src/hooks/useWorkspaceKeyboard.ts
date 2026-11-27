import { useEffect } from 'react';
import { WORKSPACE_TABS, WorkspaceTab } from '../components/WorkspaceNav';
import { RedactionMode } from '../types/pii';

interface WorkspaceKeyboardOptions {
  selectTab: (tab: WorkspaceTab) => void;
  setMode: (mode: RedactionMode) => void;
  onDownload: () => void;
  onOpenPromptLog: () => void;
  onCloseProofLog: () => void;
}

function isEditableTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable;
}

/**
 * Registers global workspace shortcuts (Alt+1..4 tabs, 1..3 modes, Ctrl+D download, ? log, Esc close).
 */
export function useWorkspaceKeyboard({
  selectTab,
  setMode,
  onDownload,
  onOpenPromptLog,
  onCloseProofLog,
}: WorkspaceKeyboardOptions): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && ['1', '2', '3', '4'].includes(e.key)) {
        e.preventDefault();
        const tab = WORKSPACE_TABS[Number(e.key) - 1];
        if (tab) selectTab(tab.id);
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        onDownload();
        return;
      }
      if (isEditableTarget(e.target)) return;
      if (e.key === '1') setMode('full');
      else if (e.key === '2') setMode('partial');
      else if (e.key === '3') setMode('pseudonymize');
      else if (e.key === '?') onOpenPromptLog();
      else if (e.key === 'Escape') onCloseProofLog();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectTab, setMode, onDownload, onOpenPromptLog, onCloseProofLog]);
}
