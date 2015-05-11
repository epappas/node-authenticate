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
 * @returns {Token}
 * @constructor
 */
module.exports = function TokenModule(models, events, config) {

    /**
     *
     * @returns {*}
     * @constructor
     */
    function Token() {
        this.models = models;
        this.events = events;

        return this;
    }

    /**
     *
     * @param args
     * @param callback
     */
    Token.prototype.authenticate = function TokenAuthenticate(args, callback) {
        var method = args.method;
        var authorization = args.authorization;
        var grantType = args.grantType;
        var code = args.code;
        var redirectUri = args.redirectUri;
        // var username = args.username;
        // var password = args.password;
        var scope = args.scope;
        // var refreshToken = args.refreshToken;
        var state = args.state;
        var apiKey;
        var secret;

        if (!authorization) return err(events, callback, {statusCode: 400, message: 'No authorization header passed'});

        var pieces = authorization.split(' ', 2);

        if (!pieces || pieces.length !== 2) return err(events, callback, {statusCode: 400, message: 'Authorization header is corrupted'});
        if (pieces[0] !== 'Basic') return cb(new restify.InvalidArgumentError('Unsupported authorization method: ', pieces[0]));

        var authDetails = new Buffer(pieces[1], 'base64').toString('ascii').split(':', 2);

        if (!authDetails || authDetails.length !== 2) return cb(new restify.InvalidArgumentError('Authorization header has corrupted data'));

        apiKey = authDetails[0];
        secret = authDetails[1];

        if (!grantType) return err(events, callback, {statusCode: 400, message: 'Body does not contain grant_type parameter', state: args});

        async.waterfall([
            function (next) { // Check Secret
                this.models.aukey.get(apiKey, function (err, aukey) {
                    if (err) return next(err, null);
                    if (!aukey) return next(new Error('Arguments mismatch'), null);

                    next(null, aukey);
                });
            }.bind(this),
            function (aukey, next) { // Check Secret
                this.models.secret.checkSecret(aukey.key, secret, function(err, isOk) {
                    if (err) return next(err, null);
                    if (!isOk) return next(new Error('Arguments mismatch'), null);

                    next(null, aukey);
                });
            }.bind(this),
            function (aukey, next) { // check grant_type
                this.models.aukey.checkGrantType(aukey, grantType, function(err, isOk) {
                    if (err) return next(err, null);
                    if (!isOk) return next(new Error('Arguments mismatch'), null);

                    aukey.targetGrantType = grantType;

                    next(null, aukey);
                });
            }.bind(this)
        ], function (error, aukey) {
            if(error) return err(events, callback, {statusCode: 400, message: error, state: args});

            switch (aukey.targetGrantType) {
                case 'authorization_code':
                    this.authorizationCode(aukey, code, redirectUri, scope, state, callback);
                    break;
                // case 'password':
                //     this.password(aukey, username, password, scope, state, callback);
                //     break;
                case 'client_credentails':
                    this.clientCredentails(aukey, scope, state, callback);
                    break;
                // case 'refresh_token':
                //     this.refreshToken(aukey, refreshToken, scope, state, callback);
                //     break;
                default:
                    err(events, callback, {statusCode: 404, message: 'Grant type does not match any supported type', state: args});
                    break;
            }
        }.bind(this));
    }

    Token.prototype.authorizationCode = function TokenAuthorizationCode(aukey, codeVal, redirectUri, scope, state, callback) {

        async.waterfall([
            // Fetch codeVal
            function(codeVal, next) {
                this.models.acode.get(codeVal, function(err, codeObj) {
                    if(err) return next(err);
                    if(!codeObj) return next(new Error('Code found not match'), null);

                    next(null, codeObj);
                });
            }.bind(this),
            // check APIKey -- Should be the same as provided
            function(codeObj, next) { // check APIKey -- Should be the same as provided
                if(codeObj.relkey !== aukey.key) return next(new Error('ApiKey is not valid'));

                next(null, codeObj);
            }.bind(this),
            // check redirectUri -- Should be the same as provided
            // function(codeObj, next) {
            //     next(null, codeObj);
            // }.bind(this),
            // Remove old refreshToken (if exists) with userId-clientId pair
            // function(codeObj, next) {
            //     next(null, codeObj);
            // }.bind(this),
            // Generate new accessToken and save it
            function(codeObj, next) {
                this.models.atoken.create({
                    relkey: codeObj.relkey,
                    scope: scope
                }, function(err, atoken) {
                    if (err) return next(err, null);
                    if (!atoken) return next(new Error('No Access token was generated'), null);

                    codeObj.accessToken = atoken;

                    next(null, codeObj);
                });
            }.bind(this)
            // Generate new refreshToken and save it
            // function(scope, codeObj, next) {
            //     next(null, codeObj);
            // }.bind(this, models, scope)
        ], function(error, codeObj) {
            if (error) return err(this.events, callback, {statusCode: 400, message: error, state: args});
            if (!codeObj) return err(this.events, callback, {statusCode: 401, message: 'Unauthorized Code creation', state: args});

            callback(null, {
                state: state,
                token_type: "bearer",
                access_token: codeObj.accessToken.key,
                // refresh_token: codeObj.refreshToken,
                expires_in: (parseInt(codeObj.accessToken.expires) - Date.now()) || undefined,
                expires: codeObj.accessToken.expires
            });
        }.bind(this));
    };

    Token.prototype.clientCredentails = function TokenClientCredentails(aukey, scope, state, callback) {

        async.waterfall([
            // Check Scope
            function (next) {
                this.models.aukey.checkScope(aukey, scope, function (err, isOk) {
                    if (err) return next(err);
                    if (!isOk) return next(new Error('Bad provided Scope'), null);

                    aukey.targetScope = scope.split(' ');
                    next(null, aukey);
                })
            }.bind(this),
            // Get User by API
            // function (aukey, next) {
            //     next(null, aukey);
            // }.bind(this),
            // Generate Access Token
            function (aukey, next) {
                var scope = aukey.targetScope;

                this.models.atoken.create({
                    relkey: aukey.key,
                    scope: scope
                }, function (err, aTokenObj) {
                    if (err) return next(err);
                    if (!aTokenObj) return next(new Error('Access Token was not generated'), null);

                    aukey.targetAccessToken = aTokenObj;
                    next(null, aukey);
                });
            }.bind(this)
            // Generate Refresh Token
            // function (aukey, next) {
            //     next(null, aukey);
            // }.bind(this)
        ], function (err, atoken) {
            if (err) return callback(err);
            if (!atoken) return callback(new Error('Arguments mismatch'), null);

            callback(null, {
                state: state,
                token_type: "bearer",
                access_token: atoken.key,
                // refresh_token: atoken.targetRefreshToken,
                expires_in: (parseInt(atoken.expires) - Date.now()) || undefined,
                expires: atoken.expires
            });

        }.bind(this));
    };

    function err(events, cb, error) {
        events.emit('token:error', error);
        cb(error);
    }

    return Token;
};