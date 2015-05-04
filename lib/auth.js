'use strict';

/* -*- javascript -*- */
/* *******************************************************************
 *  @author Evangelos Pappas <epappas@evalonlabs.com>
 *  @copyright (C) 2014, evalonlabs
 *  Copyright 2015, evalonlabs
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2015 Evangelos Pappas
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *  @doc
 *
 *  @end
 * *******************************************************************/

var async = require('async');

/**
 *
 * @param models
 * @param events
 * @param config
 * @returns {Authenticate}
 * @constructor
 */
module.exports = function AuthenticateModule(models, events, config) {

    /**
     *
     * @returns {*}
     * @constructor
     */
    function Authenticate() {
        this.models = models;
        this.events = events;

        return this;
    }

    /**
     *
     * @param args
     * @param callback
     */
    Authenticate.prototype.authenticate = function AuthenticateAuthenticate(args, callback) {
        var method = String(args.method).toUpperCase();
        var redirectUri = args.redirectUri;
        var apiKey = args.apiKey;
        var responseType = args.responseType;
        var secret = args.secret;
        var scope = args.scope;
        var state = args.state;
        var decision = args.decision;
        var userSession = args.userSession;
        var grantType;

        if (!apiKey) return err(events, callback, {statusCode: 400, message: 'ApiKey is mandatory for authorization endpoint', state: args});
        if (!responseType) return err(events, callback, {statusCode: 400, message: 'ResponseType is mandatory for authorization endpoint', state: args});

        switch (responseType) {
            case 'code':
                if (!secret && method !== 'GET') return err(events, callback, {statusCode: 400, message: 'Secret is mandatory for authorization endpoint', state: args});
                grantType = 'authorization_code';

                break;
            case 'token':
                grantType = 'implicit';
                break;
            default:
                return err(events, callback, {statusCode: 400, message: 'Unknown ResponseType parameter passed', state: args});
                break;
        }

        async.waterfall([
            function(next) { // Get ApiKey
                this.models.aukey.get(apiKey, function(err, aukey) {
                    if(err) return next(err, null);
                    if(!aukey) return next(new Error('Arguments mismatch'), null);

                    next(null, aukey);
                });
            }.bind(this),
            function(aukey, next) { // Check Secret
                if (!secret) return next(null, aukey);

                this.models.secret.checkSecret(aukey.key, secret, function(err, isOk) {
                    if(err) return next(err, null);
                    if(!isOk) return next(new Error('Arguments mismatch'), null);

                    next(null, aukey);
                });
            }.bind(this),
            function(aukey, next) { // check redirectUri
                if(aukey.uriList && aukey.uriList.length) {
                    this.models.aukey.checkRedirectUri(aukey, redirectUri, function(err, isOk) {
                        if(err) return next(err, null);
                        if(!isOk) return next(new Error('Arguments mismatch'), null);

                        aukey.targetUri = redirectUri;
                        next(null, aukey);
                    });
                }
                else {
                    next(null, aukey);
                }
            }.bind(this),
            function(aukey, next) { // check grant_type
                this.models.aukey.checkGrantType(aukey, grantType, function(err, isOk) {
                    if(err) return next(err, null);
                    if(!isOk) return next(new Error('Arguments mismatch'), null);

                    aukey.targetGrantType = grantType;
                    next(null, aukey);
                });
            }.bind(this),
            function(aukey, next) { // check available scopes
                this.models.aukey.checkScope(aukey, scope, function(err, isOk) {
                    if(err) return next(err, null);
                    if(!isOk) return next(new Error('Arguments mismatch'), null);

                    aukey.targetScope = scope;
                    next(null, aukey);
                });
            }.bind(this)
        ], function(error, aukey) {
            if(error) return err(events, callback, {statusCode: 400, message: error, state: args});

            if (method === 'GET') {
                if (!userSession) {
                    return err(events, callback, {
                        statusCode: 401,
                        message: 'Empty or expired User session',
                        state: args
                    });
                }
                this.decision(aukey, userSession, callback);
            }
            else if (grantType === 'implicit') {
                this.implicit(aukey, state, callback);
            }
            else if (grantType === 'authorization_code') {
                if(!decision || decision === 0 || decision === false) {
                    return err(events, callback, {
                        statusCode: 401,
                        message: 'User denied the access to the resource',
                        state: args
                    });
                }

                this.code(decision, aukey, state, callback);
            }
            else {
                err(events, callback, {statusCode: 404, message: 'Unknown Request Method', state: args});
            }
        }.bind(this));
    };

    /**
     *
     * @param aukey
     * @param userSession
     * @param callback
     */
    Authenticate.prototype.decision = function AuthenticateDecision(aukey, userSession, callback) {
        this.models.decision.create({
            redirectUri: aukey.targetUri,
            scope: aukey.targetScope,
            state: aukey
        }, function (err, resp) {
            if (err) return callback(err);
            if (!resp || !resp.id) return callback();

            this.models.decision.get(resp.id, callback);
        }.bind(this));
    };

    /**
     *
     * @param aukey
     * @param callback
     */
    Authenticate.prototype.code = function AuthenticateCode(decision, aukey, state, callback) {
        this.models.acode.create({
            redirectUri: aukey.targetUri,
            scope: aukey.targetScope,
            state: aukey
        }, function (err, resp) {
            if (err) return callback(err);
            if (!resp || !resp.id) return callback();

            this.models.acode.get(resp.id, callback);
        }.bind(this));
    };

    /**
     *
     * @param aukey
     * @param callback
     */
    Authenticate.prototype.implicit = function AuthenticateImplicit(aukey, state, callback) {
        this.models.atoken.create({
            redirectUri: aukey.targetUri,
            scope: aukey.targetScope,
            relkey: aukey.key,
            grantTypeList: ['implicit']
        }, function (err, resp) {
            if (err) return callback(err);
            if (!resp || !resp.id) return callback();

            this.models.atoken.get(resp.id, callback);
        }.bind(this));
    };

    function err(events, cb, error) {
        events.emit('auth:error', error);
        cb(error);
    }


    return Authenticate;
};