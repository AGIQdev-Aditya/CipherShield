/**
 * Compact keyboard shortcut legend bar for power-user navigation.
 */
export function KeyboardHints() {
  return (
    <div className="kbd-hints">
      <span>
        <kbd>Alt</kbd>+<kbd>1–4</kbd> switch workspace tab
      </span>
      <span>
        <kbd>1</kbd> <kbd>2</kbd> <kbd>3</kbd> redaction mode
      </span>
      <span>
        <kbd>Ctrl</kbd>+<kbd>D</kbd> download sanitized
      </span>
      <span>
        <kbd>?</kbd> prompt log
      </span>
      <span>
        <kbd>Esc</kbd> close network log
      </span>
    </div>
  );
}
