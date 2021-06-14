// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Log } from './Log.js';
import { MetadataService } from './MetadataService.js';
import { UserInfoService } from './UserInfoService.js';
import { TokenClient } from './TokenClient.js';
import { ErrorResponse } from './ErrorResponse.js';
import { JoseUtil } from './JoseUtil.js';

const ProtocolClaims = ["nonce", "at_hash", "iat", "nbf", "exp", "aud", "iss", "c_hash"];

export class ResponseValidator {

    constructor(settings, 
        MetadataServiceCtor = MetadataService,
        UserInfoServiceCtor = UserInfoService, 
        joseUtil = JoseUtil,
        TokenClientCtor = TokenClient) {
        if (!settings) {
            Log.error("ResponseValidator.ctor: No settings passed to ResponseValidator");
            throw new Error("settings");
        }

        this._settings = settings;
        this._metadataService = new MetadataServiceCtor(this._settings);
        this._userInfoService = new UserInfoServiceCtor(this._settings);
        this._joseUtil = joseUtil;
        this._tokenClient = new TokenClientCtor(this._settings);
    }

    validateSigninResponse(state, response) {
        Log.debug("ResponseValidator.validateSigninResponse");

        return this._processSigninParams(state, response).then(response => {
            Log.debug("ResponseValidator.validateSigninResponse: state processed");
            return this._validateTokens(state, response).then(response => {
                Log.debug("ResponseValidator.validateSigninResponse: tokens validated");
                return this._processClaims(state, response).then(response => {
                    Log.debug("ResponseValidator.validateSigninResponse: claims processed");
                    return response;
                });
            });
        });
    }

    validateSignoutResponse(state, response) {
        if (state.id !== response.state) {
            Log.error("ResponseValidator.validateSignoutResponse: State does not match");
            return Promise.reject(new Error("State does not match"));
        }

        // now that we know the state matches, take the stored data
        // and set it into the response so callers can get their state
        // this is important for both success & error outcomes
        Log.debug("ResponseValidator.validateSignoutResponse: state validated");
        response.state = state.data;

        if (response.error) {
            Log.warn("ResponseValidator.validateSignoutResponse: Response was error", response.error);
            return Promise.reject(new ErrorResponse(response));
        }

        return Promise.resolve(response);
    }

    _processSigninParams(state, response) {
        if (state.id !== response.state) {
            Log.error("ResponseValidator._processSigninParams: State does not match");
            return Promise.reject(new Error("State does not match"));
        }

        if (!state.client_id) {
            Log.error("ResponseValidator._processSigninParams: No client_id on state");
            return Promise.reject(new Error("No client_id on state"));
        }

        if (!state.authority) {
            Log.error("ResponseValidator._processSigninParams: No authority on state");
            return Promise.reject(new Error("No authority on state"));
        }

        // this allows the authority to be loaded from the signin state
        if (!this._settings.authority) {
            this._settings.authority = state.authority;
        }
        // ensure we're using the correct authority if the authority is not loaded from signin state
        else if (this._settings.authority && this._settings.authority !== state.authority) {
            Log.error("ResponseValidator._processSigninParams: authority mismatch on settings vs. signin state");
            return Promise.reject(new Error("authority mismatch on settings vs. signin state"));
        }
        // this allows the client_id to be loaded from the signin state
        if (!this._settings.client_id) {
            this._settings.client_id = state.client_id;
        }
        // ensure we're using the correct client_id if the client_id is not loaded from signin state
        else if (this._settings.client_id && this._settings.client_id !== state.client_id) {
            Log.error("ResponseValidator._processSigninParams: client_id mismatch on settings vs. signin state");
            return Promise.reject(new Error("client_id mismatch on settings vs. signin state"));
        }

        // now that we know the state matches, take the stored data
        // and set it into the response so callers can get their state
        // this is important for both success & error outcomes
        Log.debug("ResponseValidator._processSigninParams: state validated");
        response.state = state.data;

        if (response.error) {
            Log.warn("ResponseValidator._processSigninParams: Response was error", response.error);
            return Promise.reject(new ErrorResponse(response));
        }

        if (state.nonce && !response.id_token) {
            Log.error("ResponseValidator._processSigninParams: Expecting id_token in response");
            return Promise.reject(new Error("No id_token in response"));
        }

        if (!state.nonce && response.id_token) {
            Log.error("ResponseValidator._processSigninParams: Not expecting id_token in response");
            return Promise.reject(new Error("Unexpected id_token in response"));
        }

        if (state.code_verifier && !response.code) {
            Log.error("ResponseValidator._processSigninParams: Expecting code in response");
            return Promise.reject(new Error("No code in response"));
        }

        if (!state.code_verifier && response.code) {
            Log.error("ResponseValidator._processSigninParams: Not expecting code in response");
            return Promise.reject(new Error("Unexpected code in response"));
        }

        if (!response.scope) {
            // if there's no scope on the response, then assume all scopes granted (per-spec) and copy over scopes from original request
            response.scope = state.scope;
        }

        return Promise.resolve(response);
    }

    _processClaims(state, response) {
        if (response.isOpenIdConnect) {
            Log.debug("ResponseValidator._processClaims: response is OIDC, processing claims");

            response.profile = this._filterProtocolClaims(response.profile);

            if (state.skipUserInfo !== true && this._settings.loadUserInfo && response.access_token) {
                Log.debug("ResponseValidator._processClaims: loading user info");

                return this._userInfoService.getClaims(response.access_token).then(claims => {
                    Log.debug("ResponseValidator._processClaims: user info claims received from user info endpoint");

                    if (claims.sub !== response.profile.sub) {
                        Log.error("ResponseValidator._processClaims: sub from user info endpoint does not match sub in id_token");
                        return Promise.reject(new Error("sub from user info endpoint does not match sub in id_token"));
                    }

                    response.profile = this._mergeClaims(response.profile, claims);
                    Log.debug("ResponseValidator._processClaims: user info claims received, updated profile:", response.profile);

                    return response;
                });
            }
            else {
                Log.debug("ResponseValidator._processClaims: not loading user info");
            }
        }
        else {
            Log.debug("ResponseValidator._processClaims: response is not OIDC, not processing claims");
        }

        return Promise.resolve(response);
    }

    _mergeClaims(claims1, claims2) {
        var result = Object.assign({}, claims1);

        for (let name in claims2) {
            var values = claims2[name];
            if (!Array.isArray(values)) {
                values = [values];
            }

            for (let i = 0; i < values.length; i++) {
                let value = values[i];
                if (!result[name]) {
                    result[name] = value;
                }
                else if (Array.isArray(result[name])) {
                    if (result[name].indexOf(value) < 0) {
                        result[name].push(value);
                    }
                }
                else if (result[name] !== value) {
                    if (typeof value === 'object' && this._settings.mergeClaims) {
                        result[name] = this._mergeClaims(result[name], value);
                    }
                    else {
                        result[name] = [result[name], value];
                    }
                }
            }
        }

        return result;
    }

    _filterProtocolClaims(claims) {
        Log.debug("ResponseValidator._filterProtocolClaims, incoming claims:", claims);

        var result = Object.assign({}, claims);

        if (this._settings._filterProtocolClaims) {
            ProtocolClaims.forEach(type => {
                delete result[type];
            });

            Log.debug("ResponseValidator._filterProtocolClaims: protocol claims filtered", result);
        }
        else {
            Log.debug("ResponseValidator._filterProtocolClaims: protocol claims not filtered")
        }

        return result;
    }

    _validateTokens(state, response) {
        if (response.code) {
            Log.debug("ResponseValidator._validateTokens: Validating code");
            return this._processCode(state, response);
        }

        if (response.id_token) {
            if (response.access_token) {
                Log.debug("ResponseValidator._validateTokens: Validating id_token and access_token");
                return this._validateIdTokenAndAccessToken(state, response);
            }

            Log.debug("ResponseValidator._validateTokens: Validating id_token");
            return this._validateIdToken(state, response);
        }

        Log.debug("ResponseValidator._validateTokens: No code to process or id_token to validate");
        return Promise.resolve(response);
    }

    _processCode(state, response) {
        var request = {
            client_id: state.client_id,
            client_secret: state.client_secret,
            code : response.code,
            redirect_uri: state.redirect_uri,
            code_verifier: state.code_verifier
        };

        if (state.extraTokenParams && typeof(state.extraTokenParams) === 'object') {
            Object.assign(request, state.extraTokenParams);
        }
        
        return this._tokenClient.exchangeCode(request).then(tokenResponse => {
            
            for (var key in tokenResponse) {
                if (Object.prototype.hasOwnProperty.call(tokenResponse, key)) {
                    response[key] = tokenResponse[key];
                }
            }

            if (response.id_token) {
                Log.debug("ResponseValidator._processCode: token response successful, processing id_token");
                return this._validateIdTokenAttributes(state, response);
            }
            else {
                Log.debug("ResponseValidator._processCode: token response successful, returning response");
            }
            
            return response;
        });
    }

    _validateIdTokenAttributes(state, response) {
        return this._metadataService.getIssuer().then(issuer => {

            let audience = state.client_id;
            let clockSkewInSeconds = this._settings.clockSkew;
            Log.debug("ResponseValidator._validateIdTokenAttributes: Validaing JWT attributes; using clock skew (in seconds) of: ", clockSkewInSeconds);

            return this._settings.getEpochTime().then(now => {
                return this._joseUtil.validateJwtAttributes(response.id_token, issuer, audience, clockSkewInSeconds, now).then(payload => {
                
                    if (state.nonce && state.nonce !== payload.nonce) {
                        Log.error("ResponseValidator._validateIdTokenAttributes: Invalid nonce in id_token");
                        return Promise.reject(new Error("Invalid nonce in id_token"));
                    }
    
                    if (!payload.sub) {
                        Log.error("ResponseValidator._validateIdTokenAttributes: No sub present in id_token");
                        return Promise.reject(new Error("No sub present in id_token"));
                    }
    
                    response.profile = payload;
                    return response;
                });
            });
        });
    }

    _validateIdTokenAndAccessToken(state, response) {
        return this._validateIdToken(state, response).then(response => {
            return this._validateAccessToken(response);
        });
    }

    _getSigningKeyForJwt(jwt) {
        return this._metadataService.getSigningKeys().then(keys => {
            const kid = jwt.header.kid;
            if (!keys) {
                Log.error("ResponseValidator._validateIdToken: No signing keys from metadata");
                return Promise.reject(new Error("No signing keys from metadata"));
            }

            Log.debug("ResponseValidator._validateIdToken: Received signing keys");
            let key;
            if (!kid) {
                keys = this._filterByAlg(keys, jwt.header.alg);

                if (keys.length > 1) {
                    Log.error("ResponseValidator._validateIdToken: No kid found in id_token and more than one key found in metadata");
                    return Promise.reject(new Error("No kid found in id_token and more than one key found in metadata"));
                } else {
                    // kid is mandatory only when there are multiple keys in the referenced JWK Set document
                    // see http://openid.net/specs/openid-connect-core-1_0.html#Signing
                    key = keys[0];
                }
            } else {
                key = keys.filter(key => {
                    return key.kid === kid;
                })[0];
            }
            return Promise.resolve(key);
        });
    }

    _getSigningKeyForJwtWithSingleRetry(jwt) {
        return this._getSigningKeyForJwt(jwt).then(key => {
            // Refreshing signingKeys if no suitable verification key is present for given jwt header.
            if (!key) {
                // set to undefined, to trigger network call to jwks_uri.
                this._metadataService.resetSigningKeys();
                return this._getSigningKeyForJwt(jwt);
            } else {
                return Promise.resolve(key);
            }
        });
    }

    _validateIdToken(state, response) {
        if (!state.nonce) {
            Log.error("ResponseValidator._validateIdToken: No nonce on state");
            return Promise.reject(new Error("No nonce on state"));
        }

        let jwt = this._joseUtil.parseJwt(response.id_token);
        if (!jwt || !jwt.header || !jwt.payload) {
            Log.error("ResponseValidator._validateIdToken: Failed to parse id_token", jwt);
            return Promise.reject(new Error("Failed to parse id_token"));
        }

        if (state.nonce !== jwt.payload.nonce) {
            Log.error("ResponseValidator._validateIdToken: Invalid nonce in id_token");
            return Promise.reject(new Error("Invalid nonce in id_token"));
        }

        return this._metadataService.getIssuer().then(issuer => {
            Log.debug("ResponseValidator._validateIdToken: Received issuer");
            return this._getSigningKeyForJwtWithSingleRetry(jwt).then(key => {
                if (!key) {
                    Log.error("ResponseValidator._validateIdToken: No key matching kid or alg found in signing keys");
                    return Promise.reject(new Error("No key matching kid or alg found in signing keys"));
                }

                let audience = state.client_id;

                let clockSkewInSeconds = this._settings.clockSkew;
                Log.debug("ResponseValidator._validateIdToken: Validaing JWT; using clock skew (in seconds) of: ", clockSkewInSeconds);

                return this._joseUtil.validateJwt(response.id_token, key, issuer, audience, clockSkewInSeconds).then(()=>{
                    Log.debug("ResponseValidator._validateIdToken: JWT validation successful");

                    if (!jwt.payload.sub) {
                        Log.error("ResponseValidator._validateIdToken: No sub present in id_token");
                        return Promise.reject(new Error("No sub present in id_token"));
                    }

                    response.profile = jwt.payload;

                    return response;
                });
            });
        });
    }

    _filterByAlg(keys, alg){
        var kty = null;
        if (alg.startsWith("RS")) {
            kty = "RSA";
        }
        else if (alg.startsWith("PS")) {
            kty = "PS";
        }
        else if (alg.startsWith("ES")) {
            kty = "EC";
        }
        else {
            Log.debug("ResponseValidator._filterByAlg: alg not supported: ", alg);
            return [];
        }

        Log.debug("ResponseValidator._filterByAlg: Looking for keys that match kty: ", kty);

        keys = keys.filter(key => {
            return key.kty === kty;
        });

        Log.debug("ResponseValidator._filterByAlg: Number of keys that match kty: ", kty, keys.length);

        return keys;
    }

    _validateAccessToken(response) {
        if (!response.profile) {
            Log.error("ResponseValidator._validateAccessToken: No profile loaded from id_token");
            return Promise.reject(new Error("No profile loaded from id_token"));
        }

        if (!response.profile.at_hash) {
            Log.error("ResponseValidator._validateAccessToken: No at_hash in id_token");
            return Promise.reject(new Error("No at_hash in id_token"));
        }

        if (!response.id_token) {
            Log.error("ResponseValidator._validateAccessToken: No id_token");
            return Promise.reject(new Error("No id_token"));
        }

        let jwt = this._joseUtil.parseJwt(response.id_token);
        if (!jwt || !jwt.header) {
            Log.error("ResponseValidator._validateAccessToken: Failed to parse id_token", jwt);
            return Promise.reject(new Error("Failed to parse id_token"));
        }

        var hashAlg = jwt.header.alg;
        if (!hashAlg || hashAlg.length !== 5) {
            Log.error("ResponseValidator._validateAccessToken: Unsupported alg:", hashAlg);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        var hashBits = hashAlg.substr(2, 3);
        if (!hashBits) {
            Log.error("ResponseValidator._validateAccessToken: Unsupported alg:", hashAlg, hashBits);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        hashBits = parseInt(hashBits);
        if (hashBits !== 256 && hashBits !== 384 && hashBits !== 512) {
            Log.error("ResponseValidator._validateAccessToken: Unsupported alg:", hashAlg, hashBits);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        let sha = "sha" + hashBits;
        var hash = this._joseUtil.hashString(response.access_token, sha);
        if (!hash) {
            Log.error("ResponseValidator._validateAccessToken: access_token hash failed:", sha);
            return Promise.reject(new Error("Failed to validate at_hash"));
        }

        var left = hash.substr(0, hash.length / 2);
        var left_b64u = this._joseUtil.hexToBase64Url(left);
        if (left_b64u !== response.profile.at_hash) {
            Log.error("ResponseValidator._validateAccessToken: Failed to validate at_hash", left_b64u, response.profile.at_hash);
            return Promise.reject(new Error("Failed to validate at_hash"));
        }

        Log.debug("ResponseValidator._validateAccessToken: success");

        return Promise.resolve(response);
    }
}
