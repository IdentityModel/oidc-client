// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Log } from './Log.js';
import { Global } from './Global.js';
import { ErrorResponse } from "./ErrorResponse.js";

export class JsonService {
    constructor(
        additionalContentTypes = null, 
        XMLHttpRequestCtor = Global.XMLHttpRequest, 
        jwtHandler = null
    ) {
        if (additionalContentTypes && Array.isArray(additionalContentTypes))
        {
            this._contentTypes = additionalContentTypes.slice();
        }
        else
        {
            this._contentTypes = [];
        }
        this._contentTypes.push('application/json');
        if (jwtHandler) {
            this._contentTypes.push('application/jwt');
        }

        this._XMLHttpRequest = XMLHttpRequestCtor;
        this._jwtHandler = jwtHandler;
    }

    getJson(url, token) {
        if (!url){
            Log.error("JsonService.getJson: No url passed");
            throw new Error("url");
        }

        Log.debug("JsonService.getJson, url: ", url);

        return new Promise((resolve, reject) => {

            var req = new this._XMLHttpRequest();
            req.open('GET', url);

            var allowedContentTypes = this._contentTypes;
            var jwtHandler = this._jwtHandler;

            req.onload = function() {
                Log.debug("JsonService.getJson: HTTP response received, status", req.status);

                if (req.status === 200) {

                    var contentType = req.getResponseHeader("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found == "application/jwt") {
                            jwtHandler(req).then(resolve, reject);
                            return;
                        }

                        if (found) {
                            try {
                                resolve(JSON.parse(req.responseText));
                                return;
                            }
                            catch (e) {
                                Log.error("JsonService.getJson: Error parsing JSON response", e.message);
                                reject(e);
                                return;
                            }
                        }
                    }

                    reject(Error("Invalid response Content-Type: " + contentType + ", from URL: " + url));
                }
                else {
                    reject(Error(req.statusText + " (" + req.status + ")"));
                }
            };

            req.onerror = function() {
                Log.error("JsonService.getJson: network error");
                reject(Error("Network Error"));
            };

            if (token) {
                Log.debug("JsonService.getJson: token passed, setting Authorization header");
                req.setRequestHeader("Authorization", "Bearer " + token);
            }

            req.send();
        });
    }

    postForm(url, payload, basicAuth) {
        if (!url){
            Log.error("JsonService.postForm: No url passed");
            throw new Error("url");
        }

        Log.debug("JsonService.postForm, url: ", url);

        return new Promise((resolve, reject) => {

            var req = new this._XMLHttpRequest();
            req.open('POST', url);

            var allowedContentTypes = this._contentTypes;

            req.onload = function() {
                Log.debug("JsonService.postForm: HTTP response received, status", req.status);

                if (req.status === 200) {

                    var contentType = req.getResponseHeader("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found) {
                            try {
                                resolve(JSON.parse(req.responseText));
                                return;
                            }
                            catch (e) {
                                Log.error("JsonService.postForm: Error parsing JSON response", e.message);
                                reject(e);
                                return;
                            }
                        }
                    }

                    reject(Error("Invalid response Content-Type: " + contentType + ", from URL: " + url));
                    return;
                }

                if (req.status === 400) {

                    var contentType = req.getResponseHeader("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found) {
                            try {
                                var payload = JSON.parse(req.responseText);
                                if (payload && payload.error) {
                                    Log.error("JsonService.postForm: Error from server: ", payload.error);
                                    reject(new ErrorResponse(payload));
                                    return;
                                }
                            }
                            catch (e) {
                                Log.error("JsonService.postForm: Error parsing JSON response", e.message);
                                reject(e);
                                return;
                            }
                        }
                    }
                }

                reject(Error(req.statusText + " (" + req.status + ")"));
            };

            req.onerror = function() {
                Log.error("JsonService.postForm: network error");
                reject(Error("Network Error"));
            };

            let body = "";
            for(let key in payload) {

                let value = payload[key];

                if (value) {

                    if (body.length > 0) {
                        body += "&";
                    }

                    body += encodeURIComponent(key);
                    body += "=";
                    body += encodeURIComponent(value);
                }
            }

            req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

            if (basicAuth !== undefined)
            {
                req.setRequestHeader("Authorization", "Basic " + btoa(basicAuth));
            }

            req.send(body);
        });
    }
}
