
import { TokenInvalidError } from './TokenInvalidError';

export class TokenExpiredError extends TokenInvalidError {
  constructor(...args) {
    super(...args);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenExpiredError);
    }

    this.name = 'TokenExpiredError';
  }
}
