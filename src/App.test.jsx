import { fireEvent, render, screen } from '@testing-library/react';
import { expect, test } from 'vitest';
import App from './App';

test('renders the command center, case context, and independent scroll regions', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /command center/i })).toBeDefined();
  expect(screen.getByRole('navigation', { name: /forensic workspace navigation/i })).toBeDefined();
  expect(screen.getByLabelText(/active evidence/i)).toBeDefined();
  expect(screen.getByLabelText(/selected evidence/i)).toBeDefined();
  const sidebar = document.querySelector('[data-scroll-region="sidebar"]');
  const workspace = document.querySelector('[data-scroll-region="main-workspace"]');
  expect(sidebar).toBeDefined();
  expect(workspace).toBeDefined();
  expect(screen.getByRole('navigation', { name: /forensic workspace navigation/i }).querySelectorAll('a')).toHaveLength(0);
  expect(screen.getByLabelText(/case id/i)).toBeDefined();
  expect(screen.getByLabelText(/custodian name/i)).toBeDefined();
});

test('navigation switches between dedicated workspaces instead of scrolling to page anchors', () => {
  render(<App />);
  const root = document.querySelector('.locker-app');
  const workspaces = [
    ['Evidence Locker', 'evidence', 'Evidence Locker'],
    ['EXIF Analysis', 'exif', 'EXIF Analysis'],
    ['Windows Registry', 'registry', 'Windows Registry'],
    ['PCAP Analysis', 'pcap', 'PCAP Analysis'],
    ['SQLite Analysis', 'sqlite', 'SQLite Analysis'],
    ['Timeline', 'timeline', 'Investigation Timeline'],
    ['Reports', 'reports', 'Investigation Reports'],
  ];

  for (const [label, workspace, heading] of workspaces) {
    fireEvent.click(screen.getByRole('button', { name: new RegExp(label, 'i') }));
    expect(root.dataset.activeWorkspace).toBe(workspace);
    expect(screen.getByRole('heading', { level: 1, name: heading })).toBeDefined();
    expect(screen.getByRole('button', { name: new RegExp(label, 'i') }).getAttribute('aria-current')).toBe('page');
  }

  fireEvent.click(screen.getByRole('button', { name: /timeline/i }));
  expect(screen.getByLabelText(/timeline case/i)).toBeDefined();
  fireEvent.click(screen.getByRole('button', { name: /^reports$/i }));
  expect(screen.getByRole('heading', { name: /final investigation report/i })).toBeDefined();
});

test('opens an expandable Copilot chat panel from the bottom sidebar launcher', () => {
  render(<App />);
  const launcher = screen.getByRole('button', { name: /open ai copilot chat/i });
  expect(launcher.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(launcher);

  const panel = screen.getByRole('dialog', { name: /ai forensic copilot/i });
  expect(panel.getAttribute('aria-modal')).toBe('false');
  expect(screen.getByLabelText(/investigation question/i)).toBeDefined();
  expect(document.activeElement).toBe(screen.getByLabelText(/investigation question/i));
  expect(screen.getByRole('button', { name: /^send$/i })).toBeDefined();
  expect(screen.getByText('AI Copilot unavailable — secure AI provider configuration required.')).toBeDefined();

  fireEvent.click(screen.getByRole('button', { name: /minimize ai copilot chat/i }));
  expect(screen.queryByLabelText(/investigation question/i)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /restore ai copilot chat/i }));
  expect(screen.getByLabelText(/investigation question/i)).toBeDefined();

  fireEvent.click(screen.getByRole('button', { name: /expand ai copilot chat/i }));
  expect(screen.getByRole('button', { name: /restore ai copilot chat size/i }).getAttribute('aria-expanded')).toBe('true');
  fireEvent.keyDown(window, { key: 'Escape' });
  expect(screen.queryByRole('dialog', { name: /ai forensic copilot/i })).toBeNull();
  expect(document.activeElement).toBe(launcher);
  fireEvent.click(launcher);
  fireEvent.click(screen.getByRole('button', { name: /close ai copilot chat/i }));
  expect(screen.queryByRole('dialog', { name: /ai forensic copilot/i })).toBeNull();
});

test('collapses and expands the left navigation', () => {
  render(<App />);
  const collapseButton = screen.getByRole('button', { name: /collapse navigation/i });

  fireEvent.click(collapseButton);
  expect(screen.getByRole('button', { name: /expand navigation/i })).toBeDefined();

  fireEvent.click(screen.getByRole('button', { name: /expand navigation/i }));
  expect(screen.getByRole('button', { name: /collapse navigation/i })).toBeDefined();
});
