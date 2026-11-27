export interface ToastState {
  message: string;
  undoAllowlist?: string;
}

interface ToastBannerProps {
  toast: ToastState | null;
  onUndoAllowlist: (previousAllowlist: string) => void;
  onDismiss: () => void;
}

/**
 * Accessible status toast with one-click allowlist undo action.
 */
export function ToastBanner({ toast, onUndoAllowlist, onDismiss }: ToastBannerProps) {
  if (!toast) return null;
  const undoAllowlist = toast.undoAllowlist;

  return (
    <div className="toast" role="status">
      <span>{toast.message}</span>
      {undoAllowlist !== undefined && (
        <button type="button" className="btn btn-compact" onClick={() => onUndoAllowlist(undoAllowlist)}>
          Undo
        </button>
      )}
      <button type="button" className="btn btn-compact" onClick={onDismiss} aria-label="Dismiss notification">
        Dismiss
      </button>
    </div>
  );
}
