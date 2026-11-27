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
  });

  it('safely renders XSS probe strings as plain text without injecting script nodes', () => {
    const { container } = render(<App />);
    expect(container.querySelectorAll('script').length).toBe(0);
    const pre = screen.getByLabelText('Sanitized output preview');
    expect(pre.textContent).toContain("<script>alert('xss_test')</script>");
  });

  it('switches redaction modes cleanly on click and keyboard ArrowRight', () => {
    render(<App />);
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
    const emailBtn = screen.getByRole('button', { name: /Emails/i });
    expect(emailBtn.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(emailBtn);
    expect(emailBtn.getAttribute('aria-pressed')).toBe('false');
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('aarav.kulkarni@fintech-corp.in');

    const allowlistInput = screen.getByLabelText(/Allowlist \(Comma-separated/i);
    fireEvent.change(allowlistInput, { target: { value: '127.0.0.1, 10.0.14.22' } });
    expect(screen.getByLabelText('Sanitized output preview').textContent).toContain('10.0.14.22');
  });

  it('passes axe-core automated WCAG accessibility audit with zero violations', async () => {
    const { container } = render(<App />);
    const results = await axe.run(container, {
      rules: {
        // jsdom does not render full CSS layout/contrast computation
        'color-contrast': { enabled: false },
      },
    });
    expect(results.violations).toEqual([]);
  });
});
