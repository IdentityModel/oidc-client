// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { JoseUtil as JoseUtilRsa } from '../../src/JoseUtilRsa';
import { JoseUtil as JoseUtilJsrsasign } from '../../src/JoseUtil';
import { Log } from '../../src/Log';

// Node.js does not provide global atob/btoa functions that are widely supported by browsers (incl IE10)
// https://caniuse.com/#feat=atob-btoa
global.atob = (val) => { return Buffer.from(val, 'base64') };
global.btoa = (val) => { return Buffer.from(val).toString('base64') };

import chai from 'chai';

chai.should();
let expect = chai.expect;

[JoseUtilJsrsasign, JoseUtilRsa].forEach(JoseUtil => {
    const isRSA = JoseUtil === JoseUtilRsa;
    const describeStr = `JoseUtil (${isRSA ? 'rsa' : 'jsrsasign'})`;

    describe(describeStr, function () {

        let jwt;
        let jwtFromRsa;
        let rsaKey;
        let ecKey;

        const expectedIssuer = "https://localhost:44333/core";
        const expectedAudience = "js.tokenmanager";
        const notBefore = 1459129901;
        const issuedAt = notBefore;
        const expires = 1459130201;

        const expectedNow = notBefore;

        beforeEach(function () {
            Log.logger = console;
            Log.level = Log.NONE;

            jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImEzck1VZ01Gdjl0UGNsTGE2eUYzekFrZnF1RSIsImtpZCI6ImEzck1VZ01Gdjl0UGNsTGE2eUYzekFrZnF1RSJ9.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzMy9jb3JlIiwiYXVkIjoianMudG9rZW5tYW5hZ2VyIiwiZXhwIjoxNDU5MTMwMjAxLCJuYmYiOjE0NTkxMjk5MDEsIm5vbmNlIjoiNzIyMTAwNTIwOTk3MjM4MiIsImlhdCI6MTQ1OTEyOTkwMSwiYXRfaGFzaCI6IkpnRFVDeW9hdEp5RW1HaWlXYndPaEEiLCJzaWQiOiIwYzVmMDYxZTYzOThiMWVjNmEwYmNlMmM5NDFlZTRjNSIsInN1YiI6Ijg4NDIxMTEzIiwiYXV0aF90aW1lIjoxNDU5MTI5ODk4LCJpZHAiOiJpZHNydiIsImFtciI6WyJwYXNzd29yZCJdfQ.f6S1Fdd0UQScZAFBzXwRiVsUIPQnWZLSe07kdtjANRZDZXf5A7yDtxOftgCx5W0ONQcDFVpLGPgTdhp7agZkPpCFutzmwr0Rr9G7E7mUN4xcIgAABhmRDfzDayFBEu6VM8wEWTChezSWtx2xG_2zmVJxxmNV0jvkaz0bu7iin-C_UZg6T-aI9FZDoKRGXZP9gF65FQ5pQ4bCYQxhKcvjjUfs0xSHGboL7waN6RfDpO4vvVR1Kz-PQhIRyFAJYRuoH4PdMczHYtFCb-k94r-7TxEU0vp61ww4WntbPvVWwUbCUgsEtmDzAZT-NEJVhWztNk1ip9wDPXzZ2hEhDAPJ7A";

            jwtFromRsa = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImEzck1VZ01Gdjl0UGNsTGE2eUYzekFrZnF1RSIsImtpZCI6ImEzck1VZ01Gdjl0UGNsTGE2eUYzekFrZnF1RSJ9.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo0NDMzMy9jb3JlIiwiYXVkIjoianMudG9rZW5tYW5hZ2VyIiwiZXhwIjoxNDU5MTMwMjAxLCJuYmYiOjE0NTkxMjk5MDEsIm5vbmNlIjoiNzIyMTAwNTIwOTk3MjM4MiIsImlhdCI6MTQ1OTEyOTkwMSwiYXRfaGFzaCI6IkpnRFVDeW9hdEp5RW1HaWlXYndPaEEiLCJzaWQiOiIwYzVmMDYxZTYzOThiMWVjNmEwYmNlMmM5NDFlZTRjNSIsInN1YiI6Ijg4NDIxMTEzIiwiYXV0aF90aW1lIjoxNDU5MTI5ODk4LCJpZHAiOiJpZHNydiIsImFtciI6WyJwYXNzd29yZCJdfQ.f6S1Fdd0UQScZAFBzXwRiVsUIPQnWZLSe07kdtjANRZDZXf5A7yDtxOftgCx5W0ONQcDFVpLGPgTdhp7agZkPpCFutzmwr0Rr9G7E7mUN4xcIgAABhmRDfzDayFBEu6VM8wEWTChezSWtx2xG_2zmVJxxmNV0jvkaz0bu7iin-C_UZg6T-aI9FZDoKRGXZP9gF65FQ5pQ4bCYQxhKcvjjUfs0xSHGboL7waN6RfDpO4vvVR1Kz-PQhIRyFAJYRuoH4PdMczHYtFCb-k94r-7TxEU0vp61ww4WntbPvVWwUbCUgsEtmDzAZT-NEJVhWztNk1ip9wDPXzZ2hEhDAPJ7A";

            rsaKey = {
                kty: "RSA",
                use: "sig",
                kid: "a3rMUgMFv9tPclLa6yF3zAkfquE",
                x5t: "a3rMUgMFv9tPclLa6yF3zAkfquE",
                e: "AQAB",
                n: "qnTksBdxOiOlsmRNd-mMS2M3o1IDpK4uAr0T4_YqO3zYHAGAWTwsq4ms-NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4_O-0ILAlXw8NU4-jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj-x6daOv5FmrHU1r9_bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFw",
                x5c: [
                    "MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrNA6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEFBQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCHQUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pivqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmbrb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xGvQb3VHSTVVbeei0CfXoW6iz1"
                ]
            };

            ecKey = {
                kty: "EC",
                kid: "4",
                use: "sig",
                alg: "EC",
                crv: "P-256",
                x: "eZXWiRe0I3TvHPXiGnvO944gjF1o4UmitH2CVwYIrPg",
                y: "AKFNss7S35tOsp5iY7-YuLGs2cLrTKFk80JvgVzMPHQ3",
                x5c: [
                    "MIIBpDCCAUoCgYBCs6x21IvwVHFgJxiRegyHdSiEHFur9Wj2qM5oNkv6sFbbC75L849qCgMEzdtqIhCiCnFg6PaQdswHkcclXix+y0sycyIM6l429faY3jz5eQs5SYwXYkENStzTZBsWK6u7bPiV3HvjnIv+r1af8nvO5F0tiH0TC+auDj9FgRmYljAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMVoXDTE0MDIxMTIxMjQxMVowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmV1okXtCN07xz14hp7zveOIIxdaOFJorR9glcGCKz4oU2yztLfm06ynmJjv5i4sazZwutMoWTzQm+BXMw8dDcwCgYIKoZIzj0EAwIDSAAwRQIhAI4aRAoTVm3was6UimA1lFL2RId+t/fExaviosXNKg/IAiBpZB4XXcnQISwauSJ1hXNnSEcONXdqvO5gDHu+X7QHLg=="
                ]
            };
        });

        describe("parseJwt", function () {

            it("should parse a jwt", function () {

                var result = JoseUtil.parseJwt(jwt);
                result.should.be.ok;
                result.header.should.be.ok;
                result.payload.should.be.ok;

                result.header.should.deep.equal({
                    "typ": "JWT",
                    "alg": "RS256",
                    "x5t": "a3rMUgMFv9tPclLa6yF3zAkfquE",
                    "kid": "a3rMUgMFv9tPclLa6yF3zAkfquE"
                });

                result.payload.should.deep.equal({
                    "iss": "https://localhost:44333/core",
                    "aud": "js.tokenmanager",
                    "exp": 1459130201,
                    "nbf": 1459129901,
                    "nonce": "7221005209972382",
                    "iat": 1459129901,
                    "at_hash": "JgDUCyoatJyEmGiiWbwOhA",
                    "sid": "0c5f061e6398b1ec6a0bce2c941ee4c5",
                    "sub": "88421113",
                    "auth_time": 1459129898,
                    "idp": "idsrv",
                    "amr": [
                        "password"
                    ]
                });

            });

            it("should return undefined for an invalid jwt", function () {

                var result = JoseUtil.parseJwt("junk");
                expect(result).to.be.undefined;
            });

        });


        describe("validateJwt", function () {

            if(!isRSA) {
                it("should validate from RSA X509 key (jsrsasign only)", function (done, fail) {
                    delete rsaKey.n;
                    delete rsaKey.e;

                    JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, expectedNow).then(()=>{
                        done();
                    });

                });
            }

            it("should validate from RSA exponent and modulus", function (done) {

                delete rsaKey.x5c;

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, expectedNow).then(()=>{
                    done();
                })

            });

            it("should fail for unsupported key types", function (done) {

                rsaKey.kty = "foo";

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, expectedNow).catch(e => {
                    e.message.should.contain("foo");
                    done();
                });

            });

            it("should fail for mismatched keys", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, ecKey, expectedIssuer, expectedAudience, 0, expectedNow).catch(e => {
                    e.message.should.contain("signature");
                    done();
                });

            });

            it("should not validate before nbf", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, notBefore - 1).catch(e => {
                    e.message.should.contain("iat");
                    e.name.should.equal('TokenClockError');
                    done();
                });

            });

            it("should allow nbf within clock skew", function (done) {

                var p1 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, notBefore - 1);
                var p2 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, notBefore - 10);
                Promise.all([p1, p2]).then(()=>{
                    done();
                });
            });

            it("should now allow nbf outside clock skew", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, notBefore - 11).catch(e => {
                    e.message.should.contain("iat");
                    done();
                });

            });

            it("should not validate before iat", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, issuedAt - 1).catch(e => {
                    e.message.should.contain("iat");
                    e.name.should.equal('TokenClockError');
                    done();
                });

            });

            it("should allow iat within clock skew", function (done) {

                var p1 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, issuedAt - 1);
                var p2 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, issuedAt - 10);
                Promise.all([p1, p2]).then(()=>{
                    done();
                });
            });

            it("should now allow iat outside clock skew", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, issuedAt - 11).catch(e => {
                    e.message.should.contain("iat");
                    e.name.should.equal('TokenClockError');
                    done();
                });

            });

            it("should not validate after exp", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 0, expires + 1).catch(e => {
                    e.message.should.contain("exp");
                    e.name.should.equal('TokenExpiredError');
                    done();
                });

            });

            it("should allow exp within clock skew", function (done) {

                var p1 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, expires + 1);
                var p2 = JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, expires + 10)
                Promise.all([p1, p2]).then(()=>{
                    done();
                });
            });

            it("should now allow exp outside clock skew", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, expectedAudience, 10, expires + 11).catch(e => {
                    e.message.should.contain("exp");
                    e.name.should.equal('TokenExpiredError');
                    done();
                });

            });

            it("should not validate for invalid audience", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, expectedIssuer, "invalid aud", 0, expectedNow).catch(e => {
                    e.message.should.contain("aud");
                    e.name.should.equal('TokenAttributeInvalidError');
                    e.attribute.should.equal('aud');
                    done();
                });
            });

            it("should not validate for invalid issuer", function (done) {

                JoseUtil.validateJwt(jwtFromRsa, rsaKey, "invalid issuer", expectedAudience, 0, expectedNow).catch(e => {
                    e.message.should.contain("issuer");
                    e.name.should.equal('TokenAttributeInvalidError');
                    e.attribute.should.equal('iss');
                    done();
                });
            });


        });

    });
});

