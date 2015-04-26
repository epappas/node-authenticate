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

var joi = require('joi');
var bcrypt = require('bcrypt');

/**
 *
 * @param config
 * @returns {{validate: SecretModelValidate, create: SecretModelCreate, insert: SecretModelInsert, get: SecretModelGet, find: SecretModelFind, update: SecretModelUpdate, remove: SecretModelRemove, checkSecret: SecretModelcheckSecret}}
 * @constructor
 */
module.exports = function SecretModel(config) {
    var nano = config.nano;
    var db = nano.use(config.secretUrl);

    var schema = joi.object().keys({
        _id: joi.string().alphanum().default(cloneKey),
        key: joi.string().alphanum(),
        srpsalt: joi.string().default(generateSalt),
        verifier: joi.string(),
        prime: joi.string(),
        generator: joi.string(),
        userPrimeBytes: joi.string(),
        userGenerator: joi.string(),
        version: joi.string(),
        privKey: joi.string(),
        factor: joi.string(),
        created: joi.number().default(Date.now)
    });

    return {
        validate: function SecretModelValidate(value, callback) {
            if (!value) return callback(new Error('No value was given'));

            value.password = value.password || uuid.v4(uuid.v1());

            bcrypt.genSalt(10, function(err, salt) {
                bcrypt.hash(value.password, salt, function(err, hash) {
                    if (err) return callback(err);
                    value.verifier = hash;
                    value.srpsalt = salt;
                    joi.validate(value, schema, callback);
                });
            });
        },
        create: function SecretModelCreate(value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, callback);
            });
        },
        insert: function SecretModelInsert(key, value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, key || value.key, callback);
            });
        },
        get: function SecretModelGet(key, callback) {
            callback();
        },
        find: function SecretModelFind(query, callback) {
            callback();
        },
        update: function SecretModelUpdate(key, value, callback) {
            callback();
        },
        remove: function SecretModelRemove(key, callback) {
            callback();
        },
        checkSecret: function SecretModelcheckSecret(key, secretVal, callback) {
            callback();
        }
    };

    function cloneKey(context) {
        return context.key;
    }

    function generateSalt() {
        return uuid.v4(uuid.v1());
    }
};