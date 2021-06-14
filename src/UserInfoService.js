// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { JsonService } from './JsonService.js';
import { MetadataService } from './MetadataService.js';
import { Log } from './Log.js';
import { JoseUtil } from './JoseUtil.js';

export class UserInfoService {
    constructor(
        settings, 
        JsonServiceCtor = JsonService, 
        MetadataServiceCtor = MetadataService, 
        joseUtil = JoseUtil
    ) {
        if (!settings) {
            Log.error("UserInfoService.ctor: No settings passed");
            throw new Error("settings");
        }

        this._settings = settings;
        this._jsonService = new JsonServiceCtor(undefined, undefined, this._getClaimsFromJwt.bind(this), this._settings);
        this._metadataService = new MetadataServiceCtor(this._settings);
        this._joseUtil = joseUtil;
    }

    getClaims(token) {
        if (!token) {
            Log.error("UserInfoService.getClaims: No token passed");
            return Promise.reject(new Error("A token is required"));
        }

        return this._metadataService.getUserInfoEndpoint().then(url => {
            Log.debug("UserInfoService.getClaims: received userinfo url", url);

            return this._jsonService.getJson(url, token).then(claims => {
                Log.debug("UserInfoService.getClaims: claims received", claims);
                return claims;
            });
        });
    }

    _getClaimsFromJwt(req) {
        try {
            let jwt = this._joseUtil.parseJwt(req.responseText);
            if (!jwt || !jwt.header || !jwt.payload) {
                Log.error("UserInfoService._getClaimsFromJwt: Failed to parse JWT", jwt);
                return Promise.reject(new Error("Failed to parse id_token"));
            }

            var kid = jwt.header.kid;

            let issuerPromise;
            switch (this._settings.userInfoJwtIssuer) {
                case 'OP':
                    issuerPromise = this._metadataService.getIssuer();
                    break;
                case 'ANY':
                    issuerPromise = Promise.resolve(jwt.payload.iss);
                    break;
                default:
                    issuerPromise = Promise.resolve(this._settings.userInfoJwtIssuer);
                    break;
            }

            return issuerPromise.then(issuer => {
                Log.debug("UserInfoService._getClaimsFromJwt: Received issuer:" + issuer);

                return this._metadataService.getSigningKeys().then(keys => {
                    if (!keys) {
                        Log.error("UserInfoService._getClaimsFromJwt: No signing keys from metadata");
                        return Promise.reject(new Error("No signing keys from metadata"));
                    }

                    Log.debug("UserInfoService._getClaimsFromJwt: Received signing keys");
                    let key;
                    if (!kid) {
                        keys = this._filterByAlg(keys, jwt.header.alg);

                        if (keys.length > 1) {
                            Log.error("UserInfoService._getClaimsFromJwt: No kid found in id_token and more than one key found in metadata");
                            return Promise.reject(new Error("No kid found in id_token and more than one key found in metadata"));
                        }
                        else {
                            // kid is mandatory only when there are multiple keys in the referenced JWK Set document
                            // see http://openid.net/specs/openid-connect-core-1_0.html#Signing
                            key = keys[0];
                        }
                    }
                    else {
                        key = keys.filter(key => {
                            return key.kid === kid;
                        })[0];
                    }

                    if (!key) {
                        Log.error("UserInfoService._getClaimsFromJwt: No key matching kid or alg found in signing keys");
                        return Promise.reject(new Error("No key matching kid or alg found in signing keys"));
                    }

                    let audience = this._settings.client_id;

                    let clockSkewInSeconds = this._settings.clockSkew;
                    Log.debug("UserInfoService._getClaimsFromJwt: Validaing JWT; using clock skew (in seconds) of: ", clockSkewInSeconds);

                    return this._joseUtil.validateJwt(req.responseText, key, issuer, audience, clockSkewInSeconds, undefined, true).then(() => {
                        Log.debug("UserInfoService._getClaimsFromJwt: JWT validation successful");
                        return jwt.payload;
                    });
                });
            });
            return;
        }
        catch (e) {
            Log.error("UserInfoService._getClaimsFromJwt: Error parsing JWT response", e.message);
            reject(e);
            return;
        }
    }

    _filterByAlg(keys, alg) {
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
            Log.debug("UserInfoService._filterByAlg: alg not supported: ", alg);
            return [];
        }

        Log.debug("UserInfoService._filterByAlg: Looking for keys that match kty: ", kty);

        keys = keys.filter(key => {
            return key.kty === kty;
        });

        Log.debug("UserInfoService._filterByAlg: Number of keys that match kty: ", kty, keys.length);

        return keys;
    }
}
