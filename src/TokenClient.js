// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { JsonService } from './JsonService.js';
import { MetadataService } from './MetadataService.js';
import { Log } from './Log.js';

export class TokenClient {
    constructor(settings, JsonServiceCtor = JsonService, MetadataServiceCtor = MetadataService) {
        if (!settings) {
            Log.error("TokenClient.ctor: No settings passed");
            throw new Error("settings");
        }

        this._settings = settings;
        this._jsonService = new JsonServiceCtor(undefined, undefined, undefined, this._settings);
        this._metadataService = new MetadataServiceCtor(this._settings);
    }

    exchangeCode(args = {}) {
        args = Object.assign({}, args);

        args.grant_type = args.grant_type || "authorization_code";
        args.client_id = args.client_id || this._settings.client_id;
        args.client_secret = args.client_secret || this._settings.client_secret;
        args.redirect_uri = args.redirect_uri || this._settings.redirect_uri;

        var basicAuth = undefined;
        var client_authentication = args._client_authentication || this._settings._client_authentication;
        delete args._client_authentication;

        if (!args.code) {
            Log.error("TokenClient.exchangeCode: No code passed");
            return Promise.reject(new Error("A code is required"));
        }
        if (!args.redirect_uri) {
            Log.error("TokenClient.exchangeCode: No redirect_uri passed");
            return Promise.reject(new Error("A redirect_uri is required"));
        }
        if (!args.code_verifier) {
            Log.error("TokenClient.exchangeCode: No code_verifier passed");
            return Promise.reject(new Error("A code_verifier is required"));
        }
        if (!args.client_id) {
            Log.error("TokenClient.exchangeCode: No client_id passed");
            return Promise.reject(new Error("A client_id is required"));
        }
        if (!args.client_secret && client_authentication == "client_secret_basic") {
            Log.error("TokenClient.exchangeCode: No client_secret passed");
            return Promise.reject(new Error("A client_secret is required"));
        }

        // Sending the client credentials using the Basic Auth method
        if(client_authentication == "client_secret_basic")
        {
            basicAuth = args.client_id + ':' + args.client_secret;
            delete args.client_id;
            delete args.client_secret;
        }

        return this._metadataService.getTokenEndpoint(false).then(url => {
            Log.debug("TokenClient.exchangeCode: Received token endpoint");
            return this._jsonService.postForm(url, args, basicAuth).then(response => {
                Log.debug("TokenClient.exchangeCode: response received");
                return response;
            });
        });
    }

    exchangeRefreshToken(args = {}) {
        args = Object.assign({}, args);

        args.grant_type = args.grant_type || "refresh_token";
        args.client_id = args.client_id || this._settings.client_id;
        args.client_secret = args.client_secret || this._settings.client_secret;

        var basicAuth = undefined;
        var client_authentication = args._client_authentication || this._settings._client_authentication;
        delete args._client_authentication;

        if (!args.refresh_token) {
            Log.error("TokenClient.exchangeRefreshToken: No refresh_token passed");
            return Promise.reject(new Error("A refresh_token is required"));
        }
        if (!args.client_id) {
            Log.error("TokenClient.exchangeRefreshToken: No client_id passed");
            return Promise.reject(new Error("A client_id is required"));
        }

        // Sending the client credentials using the Basic Auth method
        if(client_authentication == "client_secret_basic")
        {
            basicAuth = args.client_id + ':' + args.client_secret;
            delete args.client_id;
            delete args.client_secret;
        }

        return this._metadataService.getTokenEndpoint(false).then(url => {
            Log.debug("TokenClient.exchangeRefreshToken: Received token endpoint");

            return this._jsonService.postForm(url, args, basicAuth).then(response => {
                Log.debug("TokenClient.exchangeRefreshToken: response received");
                return response;
            });
        });
    }
}
