// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Log } from './Log.js';
import { JsonService } from './JsonService.js';

const OidcMetadataUrlPath = '.well-known/openid-configuration';

export class MetadataService {
    constructor(settings, JsonServiceCtor = JsonService) {
        if (!settings) {
            Log.error("MetadataService: No settings passed to MetadataService");
            throw new Error("settings");
        }

        this._settings = settings;
        this._jsonService = new JsonServiceCtor(['application/jwk-set+json'], undefined, undefined, this._settings);
    }

    get metadataUrl() {
        if (!this._metadataUrl) {
            if (this._settings.metadataUrl) {
                this._metadataUrl = this._settings.metadataUrl;
            }
            else {
                this._metadataUrl = this._settings.authority;

                if (this._metadataUrl && this._metadataUrl.indexOf(OidcMetadataUrlPath) < 0) {
                    if (this._metadataUrl[this._metadataUrl.length - 1] !== '/') {
                        this._metadataUrl += '/';
                    }
                    this._metadataUrl += OidcMetadataUrlPath;
                }
            }
        }

        return this._metadataUrl;
    }

    resetSigningKeys() {
        this._settings = this._settings || {}
        this._settings.signingKeys = undefined
    }

    getMetadata() {
        if (this._settings.metadata) {
            Log.debug("MetadataService.getMetadata: Returning metadata from settings");
            return Promise.resolve(this._settings.metadata);
        }

        if (!this.metadataUrl) {
            Log.error("MetadataService.getMetadata: No authority or metadataUrl configured on settings");
            return Promise.reject(new Error("No authority or metadataUrl configured on settings"));
        }

        Log.debug("MetadataService.getMetadata: getting metadata from", this.metadataUrl);

        return this._jsonService.getJson(this.metadataUrl)
            .then(metadata => {
                Log.debug("MetadataService.getMetadata: json received");
                
                var seed = this._settings.metadataSeed || {};
                this._settings.metadata = Object.assign({}, seed, metadata);
                return this._settings.metadata;
            });
    }

    getIssuer() {
        return this._getMetadataProperty("issuer");
    }

    getAuthorizationEndpoint() {
        return this._getMetadataProperty("authorization_endpoint");
    }

    getUserInfoEndpoint() {
        return this._getMetadataProperty("userinfo_endpoint");
    }

    getTokenEndpoint(optional=true) {
        return this._getMetadataProperty("token_endpoint", optional);
    }

    getCheckSessionIframe() {
        return this._getMetadataProperty("check_session_iframe", true);
    }

    getEndSessionEndpoint() {
        return this._getMetadataProperty("end_session_endpoint", true);
    }

    getRevocationEndpoint() {
        return this._getMetadataProperty("revocation_endpoint", true);
    }

    getKeysEndpoint() {
        return this._getMetadataProperty("jwks_uri", true);
    }

    _getMetadataProperty(name, optional=false) {
        Log.debug("MetadataService.getMetadataProperty for: " + name);

        return this.getMetadata().then(metadata => {
            Log.debug("MetadataService.getMetadataProperty: metadata recieved");

            if (metadata[name] === undefined) {

                if (optional === true) {
                    Log.warn("MetadataService.getMetadataProperty: Metadata does not contain optional property " + name);
                    return undefined;
                }
                else {
                    Log.error("MetadataService.getMetadataProperty: Metadata does not contain property " + name);
                    throw new Error("Metadata does not contain property " + name);
                }
            }

            return metadata[name];
        });
    }

    getSigningKeys() {
        if (this._settings.signingKeys) {
            Log.debug("MetadataService.getSigningKeys: Returning signingKeys from settings");
            return Promise.resolve(this._settings.signingKeys);
        }

        return this._getMetadataProperty("jwks_uri").then(jwks_uri => {
            Log.debug("MetadataService.getSigningKeys: jwks_uri received", jwks_uri);

            return this._jsonService.getJson(jwks_uri).then(keySet => {
                Log.debug("MetadataService.getSigningKeys: key set received", keySet);

                if (!keySet.keys) {
                    Log.error("MetadataService.getSigningKeys: Missing keys on keyset");
                    throw new Error("Missing keys on keyset");
                }

                this._settings.signingKeys = keySet.keys;
                return this._settings.signingKeys;
            });
        });
    }
}
