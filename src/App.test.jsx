import { expect, test } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders the evidence locker and case controls', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /evidence locker/i })).toBeDefined();
  expect(screen.getByLabelText(/case id/i)).toBeDefined();
  expect(screen.getByLabelText(/custodian name/i)).toBeDefined();
});
