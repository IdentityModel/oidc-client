
/**
 * Generic error
 */
export class TokenInvalidError extends Error {
  constructor(...args) {
    super(...args);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenInvalidError);
    }

    this.name = 'TokenInvalidError';
  }
}
