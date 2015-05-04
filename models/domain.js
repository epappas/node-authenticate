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
var uuid = require('node-uuid');

/**
 *
 * @param config
 * @returns {{validate: DomainModelValidate, create: DomainModelCreate, insert: DomainModelInsert, get: DomainModelGet, find: DomainModelFind, update: DomainModelUpdate, remove: DomainModelRemove}}
 * @constructor
 */
module.exports = function DomainModel(config, nano) {
    config = config || {};
    var myConfig = (config.userkey = config.userkey || {});

    var db = myConfig.db || (function (myConfig, nano) {
        nano.db.get(myConfig.dbPath, function(err) {
            if (err) {
                nano.db.create(myConfig.dbPath, function(err) {
                    if (err) throw err
                });
            }
        });
        return nano.use(myConfig.dbPath);
    })(myConfig, nano);

    var schema = joi.object().keys({
        _id: joi.string().default(cloneKey, '_id'),
        key: joi.string().default(generateUuid, 'key'),
        platform: joi.string(),
        apiurl: joi.string(),
        name: joi.string(),
        created: joi.number().default(Date.now, 'created')
    });

    return {
        validate: function DomainModelValidate(value, callback) {
            joi.validate(value, schema, callback);
        },
        create: function DomainModelCreate(value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                var inserCall = value.key ?
                    db.insert.bind(db, value, value.key) :
                    db.insert.bind(db, value);

                inserCall(function (err, body, headers) {
                    if (err) return callback(err);
                    callback(null, body);
                });
            });
        },
        insert: function DomainModelInsert(key, value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, key || value.key, function (err, body, headers) {
                    if (err) return callback(err);
                    callback(null, body);
                });
            });
        },
        get: function DomainModelGet(key, callback) {
            db.get(key, function(err, body, headers) {
                if (err) return callback(err);
                callback(null, body);
            });
        },
        find: function DomainModelFind(query, callback) {
            callback();
        },
        update: function DomainModelUpdate(key, value, callback) {
            callback();
        },
        remove: function DomainModelRemove(key, callback) {
            callback();
        }
    };

    function cloneKey(context) {
        return context.key;
    }

    function generateUuid() {
        return uuid.v4(uuid.v1());
    }
};