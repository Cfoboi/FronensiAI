export type ProviderFailureCategory =
  | 'authentication'
  | 'billing_or_quota'
  | 'model_access'
  | 'rate_limit'
  | 'malformed_request'
  | 'provider_error'
  | 'network_error'
  | 'timeout'
  | 'malformed_response';

export type ProviderFailureStage =
  | 'provider_request'
  | 'provider_response'
  | 'provider_response_parse'
  | 'provider_response_validation';

export class ProviderRequestError extends Error {
  constructor(
    readonly stage: ProviderFailureStage,
    readonly category: ProviderFailureCategory,
    readonly status: number | null = null,
    readonly code: string | null = null,
  ) {
    super('AI provider request failed.');
    this.name = 'ProviderRequestError';
  }
}

function safeProviderCode(value: unknown): string | null {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,80}$/.test(value)) return null;
  return value;
}

export function classifyProviderHttpFailure(status: number, body: string): ProviderRequestError {
  let code: string | null = null;
  let providerErrorType: string | null = null;
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const error = (parsed as Record<string, unknown>).error;
      if (error && typeof error === 'object' && !Array.isArray(error)) {
        const details = error as Record<string, unknown>;
        code = safeProviderCode(details.code);
        providerErrorType = safeProviderCode(details.type);
      }
    }
  } catch {
    // Provider error bodies are untrusted; their contents are never logged.
  }

  const identifier = (code || providerErrorType || '').toLowerCase();
  let category: ProviderFailureCategory;
  if (status === 401 || identifier.includes('invalid_api_key') || identifier.includes('authentication')) {
    category = 'authentication';
  } else if (status === 402
    || identifier.includes('insufficient_quota')
    || identifier.includes('billing')
    || identifier.includes('payment_required')) {
    category = 'billing_or_quota';
  } else if (status === 403 || status === 404
    || identifier.includes('model_not_found')
    || identifier.includes('model_access')) {
    category = 'model_access';
  } else if (status === 429 || identifier.includes('rate_limit')) {
    category = 'rate_limit';
  } else if (status === 400 || identifier.includes('invalid_request') || identifier.includes('context_length')) {
    category = 'malformed_request';
  } else {
    category = 'provider_error';
  }

  return new ProviderRequestError('provider_response', category, status, code);
}

export function providerFailureForLog(error: unknown): ProviderRequestError {
  if (error instanceof ProviderRequestError) return error;
  if (error && typeof error === 'object' && 'name' in error && error.name === 'AbortError') {
    return new ProviderRequestError('provider_request', 'timeout');
  }
  return new ProviderRequestError('provider_request', 'network_error');
}
