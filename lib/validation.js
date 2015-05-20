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
 * @param self
 * @param models
 * @param events
 * @param config
 * @returns {Validation}
 * @constructor
 */
module.exports = function ValidationModule(self, models, events, config) {

    /**
     *
     * @returns {*}
     * @constructor
     */
    function Validation() {
        this.models = models;
        this.events = events;

        return this;
    }

    /**
     *
     * @param args
     * @param callback
     */
    Validation.prototype.validate = function ValidationValidate(args, callback) {
        var method = args.method;
        var accessToken = args.accessToken;
        var uniqueKey = args.uniqueKey;
        var targetScope = args.scope;
        var scope;

        this.models = models;
        this.events = events;

        if (!accessToken) return err(events, callback, {statusCode: 400, message: 'No access token provided'});
        if (!uniqueKey) return err(events, callback, {statusCode: 400, message: 'No unique key provided'});

        async.waterfall([
            function (next) { // Check token
                this.models.atoken.get(accessToken, function(err, atoken) {
                    if (err) return next(err, null);
                    if (atoken.uniqueKey !== uniqueKey) return next(new Error('Arguments mismatch'), null);

                    next(null, atoken);
                });
            }.bind(this),
            function (atoken, next) { // check scope
                this.models.atoken.checkScope(atoken, targetScope, function(err, isOk) {
                    if (err) return next(err, null);
                    if (!isOk) return next(new Error('Arguments mismatch'), null);

                    next(null, atoken);
                });
            }.bind(this),
            function (atoken, next) { // check expiration
                if (atoken.expires < Date.now()) return next(new Error('Token has expired'));

                next(null, atoken);
            }.bind(this)
        ], function (error, atoken) {
            if(error) return err(events, callback, {statusCode: 400, message: error, state: args});

            callback(null, atoken);
        }.bind(this));
    }

    function err(events, cb, error) {
        events.emit('validation:error', error);
        cb(error);
    }

    return Validation;
};