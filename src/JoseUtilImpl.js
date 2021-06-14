// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Log } from './Log.js';
import { TokenClockError } from './errors/TokenClockError';
import { TokenExpiredError } from './errors/TokenExpiredError';
import { TokenAttributeInvalidError } from './errors/TokenAttributeInvalidError';
import { TokenAttributeMissingError } from './errors/TokenAttributeMissingError';

export default function getJoseUtil({ jws, KeyUtil, X509, crypto, hextob64u, b64tohex, AllowedSigningAlgs }) {
    return class JoseUtil {

        static parseJwt(jwt) {
            Log.debug("JoseUtil.parseJwt");
            try {
                var token = jws.JWS.parse(jwt);
                return {
                    header: token.headerObj,
                    payload: token.payloadObj
                }
            } catch (e) {
                Log.error(e);
            }
        }

        static validateJwt(jwt, key, issuer, audience, clockSkew, now, timeInsensitive) {
            Log.debug("JoseUtil.validateJwt");

            try {
                if (key.kty === "RSA") {
                    if (key.e && key.n) {
                        key = KeyUtil.getKey(key);
                    } else if (key.x5c && key.x5c.length) {
                        var hex = b64tohex(key.x5c[0]);
                        key = X509.getPublicKeyFromCertHex(hex);
                    } else {
                        Log.error("JoseUtil.validateJwt: RSA key missing key material", key);
                        return Promise.reject(new Error("RSA key missing key material"));
                    }
                } else if (key.kty === "EC") {
                    if (key.crv && key.x && key.y) {
                        key = KeyUtil.getKey(key);
                    } else {
                        Log.error("JoseUtil.validateJwt: EC key missing key material", key);
                        return Promise.reject(new Error("EC key missing key material"));
                    }
                } else {
                    Log.error("JoseUtil.validateJwt: Unsupported key type", key && key.kty);
                    return Promise.reject(new Error("Unsupported key type: " + key && key.kty));
                }

                return JoseUtil._validateJwt(jwt, key, issuer, audience, clockSkew, now, timeInsensitive);
            } catch (e) {
                Log.error(e && e.message || e);

                if (e instanceof TokenInvalidError === false) {
                    e = new TokenInvalidError(e && e.message || e);
                }

                return Promise.reject(e);
            }
        }

        static validateJwtAttributes(jwt, issuer, audience, clockSkew, now, timeInsensitive) {
            if (!clockSkew) {
                clockSkew = 0;
            }

            if (!now) {
                now = parseInt(Date.now() / 1000);
            }

            var payload = JoseUtil.parseJwt(jwt).payload;

            if (!payload.iss) {
                Log.error("JoseUtil._validateJwt: issuer was not provided");
                return Promise.reject(new TokenAttributeMissingError("issuer", "issuer was not provided"));
            }
            if (payload.iss !== issuer) {
                Log.error("JoseUtil._validateJwt: Invalid issuer in token", payload.iss);
                return Promise.reject(new TokenAttributeInvalidError('iss', "Invalid issuer in token: " + payload.iss));
            }

            if (!payload.aud) {
                Log.error("JoseUtil._validateJwt: aud was not provided");
                return Promise.reject(new TokenAttributeMissingError("aud", "aud was not provided"));
            }
            var validAudience = payload.aud === audience || (Array.isArray(payload.aud) && payload.aud.indexOf(audience) >= 0);
            if (!validAudience) {
                Log.error("JoseUtil._validateJwt: Invalid audience in token", payload.aud);
                return Promise.reject(new TokenAttributeInvalidError('aud', "Invalid audience in token: " + payload.aud));
            }
            if (payload.azp && payload.azp !== audience) {
                Log.error("JoseUtil._validateJwt: Invalid azp in token", payload.azp);
                return Promise.reject(new TokenAttributeInvalidError('azp', "Invalid azp in token: " + payload.azp));
            }

            if (!timeInsensitive) {
                var lowerNow = now + clockSkew;
                var upperNow = now - clockSkew;

                if (!payload.iat) {
                    Log.error("JoseUtil._validateJwt: iat was not provided");
                    return Promise.reject(new TokenAttributeMissingError('iat', "iat was not provided"));
                }
                if (lowerNow < payload.iat) {
                    Log.error("JoseUtil._validateJwt: iat is in the future", payload.iat);
                    return Promise.reject(new TokenClockError("iat is in the future: " + payload.iat));
                }

                if (payload.nbf && lowerNow < payload.nbf) {
                    Log.error("JoseUtil._validateJwt: nbf is in the future", payload.nbf);
                    return Promise.reject(new TokenClockError("nbf is in the future: " + payload.nbf));
                }

                if (!payload.exp) {
                    Log.error("JoseUtil._validateJwt: exp was not provided");
                    return Promise.reject(new TokenAttributeMissingError('exp', "exp was not provided"));
                }
                if (payload.exp < upperNow) {
                    Log.error("JoseUtil._validateJwt: exp is in the past", payload.exp);
                    return Promise.reject(new TokenExpiredError("exp is in the past:" + payload.exp));
                }
            }

            return Promise.resolve(payload);
        }

        static _validateJwt(jwt, key, issuer, audience, clockSkew, now, timeInsensitive) {

            return JoseUtil.validateJwtAttributes(jwt, issuer, audience, clockSkew, now, timeInsensitive).then(payload => {
                try {
                    if (!jws.JWS.verify(jwt, key, AllowedSigningAlgs)) {
                        Log.error("JoseUtil._validateJwt: signature validation failed");
                        return Promise.reject(new Error("signature validation failed"));
                    }

                    return payload;
                } catch (e) {
                    Log.error(e && e.message || e);
                    return Promise.reject(new Error("signature validation failed"));
                }
            });
        }

        static hashString(value, alg) {
            try {
                return crypto.Util.hashString(value, alg);
            } catch (e) {
                Log.error(e);
            }
        }

        static hexToBase64Url(value) {
            try {
                return hextob64u(value);
            } catch (e) {
                Log.error(e);
            }
        }
    }
}
