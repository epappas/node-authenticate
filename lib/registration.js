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
     * @param regRef
     * @param callback
     */
    Registration.prototype.get = function (regRef, callback) {
        this.models.regref.get(regRef, function (err, regRef) {
            if (err) return callback(err);

            setImmediate(callback, null, regRef.state);
        });
    };

    /**
     *
     * @param email
     * @param callback
     */
    Registration.prototype.newUser = function newUser(email, callback) {
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
     * @param obj
     * @param callback
     */
    Registration.prototype.createUserKey = function createUserKey(obj, callback) {
        async.waterfall([
            this.models.userkey.create.bind(this.models.userkey, obj),
            function (resp, next) {
                this.models.userkey.get(resp.id, next);
            }.bind(this),
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

            this.models.md5key.get(md5key.id, function (err, md5key) {
                setImmediate(callback, null, md5key);
            });

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

            this.models.atoken.get(atoken.id, function (err, atoken) {
                setImmediate(callback, null, atoken);
            });

            this.events.emit('atoken:created', atoken);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createRegRef = function createRegRef(obj, callback) {
        this.models.regref.create(obj, function (err, regRef) {
            if (err) return callback(err);

            this.models.regref.get(regRef.id, function (err, regRef) {
                setImmediate(callback, null, regRef);
            });

            this.events.emit('regref:created', regRef);
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
            function (resp, next) {
                this.models.aukey.get(resp.id, next);
            }.bind(this),
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
            function (resp, next) {
                this.models.openkey.get(resp.id, next);
            }.bind(this),
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

            this.models.rsa.get(rsa.id, function (err, rsa) {
                setImmediate(callback, null, rsa);
            });

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

            this.models.salt.get(salt.id, function (err, salt) {
                setImmediate(callback, null, salt);
            });

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

            this.models.secret.get(secret.id, function (err, secret) {
                setImmediate(callback, null, secret);
            });

            this.events.emit('secret:created', secret);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createPlatform = function createPlatform(obj, callback) {
        this.models.platform.create(obj, function (err, platform) {
            if (err) return callback(err);

            this.models.platform.get(platform.id, function (err, platform) {
                setImmediate(callback, null, platform);
            });

            this.events.emit('platform:created', platform);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createDomainState = function createDomainState(obj, callback) {
        this.models.domainstate.create(obj, function (err, domainstate) {
            if (err) return callback(err);

            this.models.domainstate.get(domainstate.id, function (err, domainstate) {
                setImmediate(callback, null, domainstate);
            });

            this.events.emit('domainstate:created', domainstate);
        }.bind(this));
    };

    /**
     *
     * @param obj
     * @param callback
     */
    Registration.prototype.createDomain = function createDomain(obj, callback) {
        this.models.domain.create(obj, function (err, domain) {
            if (err) return callback(err);

            this.models.domain.get(domain.id, function (err, domain) {
                setImmediate(callback, null, domain);
            });

            this.events.emit('domain:created', domain);
        }.bind(this));
    };

    return Registration;
};