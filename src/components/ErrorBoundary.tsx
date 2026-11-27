import { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

/**
 * Prevents unexpected runtime errors from unmounting the redaction workspace.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('CipherShield UI error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <main className="app-shell">
          <div role="alert" className="panel">
            <h1 className="section-heading">CipherShield Encountered an Unexpected Error</h1>
            <p className="muted-copy">
              Your text remained strictly inside browser memory. Reload the page to reset the workspace.
            </p>
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              Reload Workspace
            </button>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
