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
 * @returns {module.Registration}
 * @constructor
 */
module.exports = function RegistrationModule(models, events, config) {

    /**
     *
     * @constructor
     */
    function Registration() {
        this.models = models;
        this.config = config;
        this.events = events;

        return this;
    }

    /**
     *
     * @param email
     * @param callback
     */
    Registration.prototype.register = function register(email, callback) {
        async.waterfall([
            // create ukey
            function (next) {
                this.createUserKey({
                    email: email
                }, next);
            }.bind(this),
            // create md5Key
            function (ukeyObj, next) {
                this.createMD5Key({
                    ukey: ukeyObj.key,
                    email: ukeyObj.email
                }, next);
            }.bind(this),
            // create openKey
            function (md5KeyObj, next) {
                this.createOpenKey({
                    ukey: md5KeyObj.ukey,
                    scope: [] // TODO
                }, next);
            }.bind(this),
            // create aukey
            function (openKeyObj, next) {
                this.createAUKey({
                    openkey: openKeyObj.key,
                    scope: [] // TODO
                }, next);
            }.bind(this),
            // create atoken
            function (auKeyObj, next) {
                this.createAToken({
                    relkey: auKeyObj.key,
                    scope: [] // TODO
                }, next);
            }.bind(this),
            // create regRef
            function (atokenObj, next) {
                this.createRegRef({
                    relkey: atokenObj.relkey,
                    scope: [], // TODO
                    state: {
                        email: email,
                        token: atokenObj.key,
                        salt: atokenObj.salt,
                        relkey: atokenObj.relkey,
                        expires: atokenObj.expires,
                        scope: atokenObj.scope
                    }
                }, next);
            }.bind(this)
        ], function (err, regRef) {
            if (err) {
                this.events.emit('register:error', {error: err, email: email});
                return callback(err);
            }

            setImmediate(callback, null, regRef);

            this.events.emit('register', regRef);
            this.events.emit('register:' + email, regRef);
        }.bind(this));
    };

    /**
     *
     * @param type
     */
    Registration.prototype.create = function create(type) {
        var args = Array.prototype.slice.call(arguments, 1);

        switch (type) {
            case 'atoken':
                this.createAToken.apply(this, args);
                break;
            case 'aukey':
                this.createAUKey.apply(this, args);
                break;
            case 'md5key':
                this.createMD5Key.apply(this, args);
                break;
            case 'openkey':
                this.createOpenKey.apply(this, args);
                break;
            case 'rsa':
                this.createRSA.apply(this, args);
                break;
            case 'salt':
                this.createSalt.apply(this, args);
                break;
            case 'secret':
                this.createSecret.apply(this, args);
                break;
            case 'userkey':
                this.createUserKey.apply(this, args);
                break;
        }
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createUserKey = function createUserKey(obj, callback) {
        async.waterfall([
            this.models.userkey.create.bind(this.models.userkey, obj),
            // crete dependencies
            function (userkey, next) {
                async.series({
                    salt: function (next) {
                        this.createSalt({
                            key: userkey.key
                        }, next);
                    }.bind(this),
                    secret: function (next) {
                        this.createSecret({
                            key: userkey.key
                        }, next);
                    }.bind(this),
                    rsa: function (next) {
                        this.createRSA({
                            key: userkey.key
                        }, next);
                    }.bind(this)
                }, function (err) {
                    next(err, userkey);
                });
            }.bind(this)
        ], function (err, userkey) {
            if (err) return callback(err);

            setImmediate(callback, null, userkey);
            this.events.emit('userkey:created', userkey);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createMD5Key = function createMD5Key(obj, callback) {
        // ukey: ukeyObj.key,
        // email: ukeyObj.email

        this.models.md5key.create(obj, function (err, md5key) {
            if (err) return callback(err);

            setImmediate(callback, null, md5key);
            this.events.emit('md5key:created', md5key);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createAToken = function createAToken(obj, callback) {
        this.models.atoken.create(obj, function (err, atoken) {
            if (err) return callback(err);

            setImmediate(callback, null, atoken);
            this.events.emit('atoken:created', atoken);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createRegRef = function createRegRef(obj, callback) {
        this.models.regRef.create(obj, function (err, atoken) {
            if (err) return callback(err);

            setImmediate(callback, null, atoken);
            this.events.emit('regref:created', atoken);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createAUKey = function createAUKey(obj, callback) {
        async.waterfall([
            this.models.aukey.create.bind(this.models.aukey, obj),
            // crete dependencies
            function (aukey, next) {
                async.series({
                    salt: function (next) {
                        this.createSalt({
                            key: aukey.key
                        }, next);
                    }.bind(this),
                    secret: function (next) {
                        this.createSecret({
                            key: aukey.key
                        }, next);
                    }.bind(this),
                    rsa: function (next) {
                        this.createRSA({
                            key: aukey.key
                        }, next);
                    }.bind(this)
                }, function (err) {
                    next(err, aukey);
                });
            }.bind(this)
        ], function (err, aukey) {
            if (err) return callback(err);

            setImmediate(callback, null, aukey);
            this.events.emit('aukey:created', aukey);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createOpenKey = function createOpenKey(obj, callback) {
        async.waterfall([
            this.models.openkey.create.bind(this.models.openkey, obj),
            // crete dependencies
            function (openkey, next) {
                async.series({
                    salt: function (next) {
                        this.createSalt({
                            key: openkey.key
                        }, next);
                    }.bind(this),
                    secret: function (next) {
                        this.createSecret({
                            key: openkey.key
                        }, next);
                    }.bind(this),
                    rsa: function (next) {
                        this.createRSA({
                            key: openkey.key
                        }, next);
                    }.bind(this)
                }, function (err) {
                    next(err, openkey);
                });
            }.bind(this)
        ], function (err, openkey) {
            if (err) return callback(err);

            setImmediate(callback, null, openkey);
            this.events.emit('openkey:created', openkey);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createRSA = function createRSA(obj, callback) {
        this.models.rsa.create(obj, function (err, rsa) {
            if (err) return callback(err);

            setImmediate(callback, null, rsa);
            this.events.emit('rsa:created', rsa);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createSalt = function createSalt(obj, callback) {
        this.models.salt.create(obj, function (err, salt) {
            if (err) return callback(err);

            setImmediate(callback, null, salt);
            this.events.emit('salt:created', salt);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createSecret = function createSecret(obj, callback) {
        this.models.secret.create(obj, function (err, secret) {
            if (err) return callback(err);

            setImmediate(callback, null, secret);
            this.events.emit('secret:created', secret);
        }.bind(this));
    };

    return Registration;
};