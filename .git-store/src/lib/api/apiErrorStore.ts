import type { ApiError } from '@/types/mcpGateway';

const MAX = 20;
const errors: ApiError[] = [];

export function pushApiError(err: ApiError) {
  errors.unshift({ ...err, details: err.details });
  if (errors.length > MAX) errors.length = MAX;
}

export function getApiErrors(): ApiError[] {
  return [...errors];
}
