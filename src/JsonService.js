// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { Log } from './Log.js';
import { Global } from './Global.js';

export class JsonService {
    constructor(
        additionalContentTypes = null,
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

        this._jwtHandler = jwtHandler;
    }

    getJson(url, token) {
        if (!url){
            Log.error("JsonService.getJson: No url passed");
            throw new Error("url");
        }

        Log.debug("JsonService.getJson, url: ", url);

        return new Promise((resolve, reject) => {
            var headers = {};
            if (token) {
                Log.debug("JsonService.getJson: token passed, setting Authorization header");
                headers["Authorization"] = "Bearer " + token;
            }

            fetch(url, {
                method: 'GET',
                headers: headers,
            }).then((response) => {
                var allowedContentTypes = this._contentTypes;
                var jwtHandler = this._jwtHandler;

                Log.debug("JsonService.getJson: HTTP response received, status", response.status);

                if (response.status === 200) {

                    var contentType = response.headers.get("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found === "application/jwt") {
                            response.text().then((text) => jwtHandler(text)).then(resolve, reject);
                            return;
                        }

                        if (found) {
                            response.json().then(resolve, (error) => {
                                Log.error("JsonService.getJson: Error parsing JSON response", error.message);
                                reject(error);
                            });
                            return;
                        }
                    }

                    reject(Error("Invalid response Content-Type: " + contentType + ", from URL: " + url));
                }
                else {
                    reject(Error(response.statusText + " (" + response.status + ")"));
                }
            }, (error) => {
                Log.error("JsonService.getJson: network error: " + error);
                reject(Error("Network Error: " + error));
            });
        });
    }

    postForm(url, payload, basicAuth) {
        if (!url){
            Log.error("JsonService.postForm: No url passed");
            throw new Error("url");
        }

        Log.debug("JsonService.postForm, url: ", url);

        return new Promise((resolve, reject) => {
            var headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            };
            if (basicAuth !== undefined) {
                headers["Authorization"] = "Basic " + btoa(basicAuth);
            }

            let body = new URLSearchParams();
            for (let key in payload) {
                let value = payload[key];

                if (value) {
                    body.set(key, value);
                }
            }

            fetch(url, {
                method: 'POST',
                headers: headers,
                body: body,
            }).then((response) => {
                var allowedContentTypes = this._contentTypes;

                Log.debug("JsonService.postForm: HTTP response received, status", response.status);

                if (response.status === 200) {

                    var contentType = response.headers.get("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found) {
                            response.json().then(resolve, (error) => {
                                Log.error("JsonService.postForm: Error parsing JSON response", error.message);
                                reject(error);
                            });
                            return;
                        }
                    }

                    reject(Error("Invalid response Content-Type: " + contentType + ", from URL: " + url));
                    return;
                }

                if (response.status === 400) {

                    var contentType = response.headers.get("Content-Type");
                    if (contentType) {

                        var found = allowedContentTypes.find(item=>{
                            if (contentType.startsWith(item)) {
                                return true;
                            }
                        });

                        if (found) {
                            response.json().then((json) => {
                                if (json && json.error) {
                                    Log.error("JsonService.postForm: Error from server: ", json.error);
                                    reject(new Error(json.error));
                                }
                                else {
                                    reject(Error(response.statusText + " (" + response.status + ")"));
                                }
                                resolve(json);
                            }, (error) => {
                                Log.error("JsonService.postForm: Error parsing JSON response", error.message);
                                reject(error);
                            });
                            return;
                        }
                    }
                }

                reject(Error(response.statusText + " (" + response.status + ")"));
            }, (error) => {
                Log.error("JsonService.postForm: network error: " + error);
                reject(Error("Network Error: " + error));
            });
        });
    }
}
