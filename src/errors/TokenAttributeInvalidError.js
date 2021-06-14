import { TokenInvalidError } from './TokenInvalidError';

export class TokenAttributeInvalidError extends TokenInvalidError {
  constructor(attribute, ...args) {
    super(...args);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenAttributeInvalidError);
    }

    this.name = 'TokenAttributeInvalidError';
    this.attribute = attribute;
  }
}
