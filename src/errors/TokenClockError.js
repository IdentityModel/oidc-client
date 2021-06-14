
import { TokenInvalidError } from './TokenInvalidError';

export class TokenClockError extends TokenInvalidError {
  constructor(...args) {
    super(...args);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenClockError);
    }

    this.name = 'TokenClockError';
  }
}
