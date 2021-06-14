import { TokenInvalidError } from './TokenInvalidError';

export class TokenAttributeMissingError extends TokenInvalidError {
  constructor(attribute, ...args) {
    super(...args);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenAttributeMissingError);
    }
    this.name = 'TokenAttributeMissingError';
    this.attribute = attribute;
  }
}
