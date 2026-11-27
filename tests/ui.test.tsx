// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import axe from 'axe-core';
import App from '../src/App';

afterEach(() => {
  cleanup();
});

describe('CipherShield UI, Security & Accessibility', () => {
  it('renders required semantic landmarks, skip link, and heading hierarchy', () => {
    const { container } = render(<App />);
    expect(container.querySelector('header')).not.toBeNull();
    expect(container.querySelector('main')).not.toBeNull();
    expect(container.querySelector('footer')).not.toBeNull();
    expect(screen.getByRole('heading', { level: 1, name: /CipherShield/i })).toBeTruthy();
    expect(screen.getByText(/Skip to main content/i)).toBeTruthy();
    expect(screen.getByText(/Network Monitor · 0 External Calls/i)).toBeTruthy();
  });

  it('safely renders XSS probe strings as plain text without injecting script nodes', () => {
    const { container } = render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /FinTech Incident Log/i }));
    expect(container.querySelectorAll('script').length).toBe(0);
    const pre = screen.getByLabelText('Sanitized output preview');
    expect(pre.textContent).toContain("<script>alert('xss_test')</script>");
  });

  it('switches redaction modes cleanly on click and keyboard ArrowRight', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /FinTech Incident Log/i }));
    const fullMaskTab = screen.getByRole('tab', { name: 'Full Mask' });
    fireEvent.click(fullMaskTab);
    expect(fullMaskTab.getAttribute('aria-selected')).toBe('true');
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('[REDACTED]');

    fireEvent.keyDown(fullMaskTab, { key: 'ArrowRight' });
    const partialTab = screen.getByRole('tab', { name: 'Partial Mask' });
    expect(partialTab.getAttribute('aria-selected')).toBe('true');
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('XXXX-XXXX-XXXX-0366');
  });

  it('activates structured CSV Column Diff when HR Payroll CSV is loaded', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /HR Payroll CSV/i }));
    expect(screen.getByText(/CSV Original vs. Sanitized Cell Comparison/i)).toBeTruthy();
  });

  it('rejects unsupported file extensions and binary null-byte payloads with an accessible alert', async () => {
    const { container } = render(<App />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const badFile = new File(['binary'], 'malware.exe', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [badFile] } });
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Unsupported file type');

    const binarySpoof = new File(['hello\u0000world'], 'fake.txt', { type: 'text/plain' });
    fireEvent.change(input, { target: { files: [binarySpoof] } });
    const binAlert = await screen.findByRole('alert');
    expect(binAlert.textContent).toContain('Binary payload rejected');
  });

  it('toggles category filters and live allowlist exclusions', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /FinTech Incident Log/i }));
    const emailBtn = screen.getByRole('button', { name: /Emails/i });
    expect(emailBtn.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(emailBtn);
    expect(emailBtn.getAttribute('aria-pressed')).toBe('false');
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('aarav.kulkarni@fintech-corp.in');

    const allowlistInput = screen.getByLabelText(/Allowlist \(Comma-separated/i);
    fireEvent.change(allowlistInput, { target: { value: '127.0.0.1, 192.168.42.108' } });
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('192.168.42.108');
  });

  it('lets users inspect detected items, keep/undo originals, toggle network proof log, run self-tests, and generate offline briefs', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /FinTech Incident Log/i }));

    // Toggle expandable Zero-Egress network proof log from navigation bar
    fireEvent.click(screen.getByRole('button', { name: /0 External Egress/i }));
    expect(screen.getByRole('region', { name: /Intercepted network events/i })).toBeTruthy();

    // Switch to Entity Review & Vault tab, click Keep Original & verify Undo toast
    fireEvent.click(screen.getByRole('tab', { name: /Entity Review & Vault/i }));
    const keepButtons = screen.getAllByRole('button', { name: /Keep Original/i });
    expect(keepButtons.length).toBeGreaterThan(0);
    fireEvent.click(keepButtons[0]);
    expect(screen.getByLabelText('Kept / Allowlisted items').textContent).toContain('aarav.kulkarni@fintech-corp.in');
    expect(screen.getByRole('status').textContent).toContain('aarav.kulkarni@fintech-corp.in');

    // Switch to Self-Test & Proof tab & verify live proof executes cleanly
    fireEvent.click(screen.getByRole('tab', { name: /Self-Test & Proof/i }));
    expect(await screen.findByText(/Live Adversarial Proof: 10\/10 Passed/i)).toBeTruthy();

    // Switch to Compliance Advisor tab & generate offline DPDP/PCI brief
    fireEvent.click(screen.getByRole('tab', { name: /Compliance Advisor/i }));
    fireEvent.click(screen.getByRole('button', { name: /Generate Offline Compliance Brief/i }));
    expect(await screen.findByText(/PCI-DSS Req 3\.4/i)).toBeTruthy();
  });

  it('supports Alt+1..4 workspace shortcuts and cycles dark/light/system themes cleanly', () => {
    render(<App />);
    fireEvent.keyDown(window, { key: '2', altKey: true });
    expect(screen.getByRole('tab', { name: /Entity Review & Vault/i }).getAttribute('aria-selected')).toBe('true');

    fireEvent.keyDown(window, { key: '3', altKey: true });
    expect(screen.getByRole('tab', { name: /Self-Test & Proof/i }).getAttribute('aria-selected')).toBe('true');

    const themeBtn = screen.getByRole('button', { name: /Switch color theme/i });
    fireEvent.click(themeBtn);
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('passes axe-core automated WCAG accessibility audit with zero violations across workspace tabs', async () => {
    const { container } = render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Try Demo Data/i }));
    fireEvent.click(screen.getByRole('button', { name: /FinTech Incident Log/i }));

    for (const tabRegex of [/Sanitize Studio/i, /Entity Review & Vault/i, /Self-Test & Proof/i, /Compliance Advisor/i]) {
      fireEvent.click(screen.getByRole('tab', { name: tabRegex }));
      const results = await axe.run(container, {
        rules: {
          // jsdom does not render full CSS layout/contrast computation
          'color-contrast': { enabled: false },
        },
      });
      expect(results.violations).toEqual([]);
    }
  });
});
