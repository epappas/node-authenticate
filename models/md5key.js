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
var crypto = require('crypto');

/**
 *
 * @param config
 * @returns {{validate: Md5KeyModelValidate, create: Md5KeyModelCreate, insert: Md5KeyModelInsert, get: Md5KeyModelGet, find: Md5KeyModelFind, update: Md5KeyModelUpdate, remove: Md5KeyModelRemove}}
 * @constructor
 */
module.exports = function Md5KeyModel(config) {
    var nano = config.nano;
    var db = nano.use(config.md5keyUrl);

    var schema = joi.object().keys({
        _id: joi.string().alphanum().default(cloneKey),
        ukey: joi.string().alphanum(),
        key: joi.string().alphanum(),
        created: joi.number().default(Date.now)
    });

    return {
        validate: function Md5KeyModelValidate(value, callback) {
            var hash = crypto.createHash('md5');
            hash.update(value.email, 'utf8');
            value.key = hash.digest('hex');

            joi.validate(value, schema, callback);
        },
        create: function Md5KeyModelCreate(value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, callback);
            });
        },
        insert: function Md5KeyModelInsert(key, value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, key || value.key, callback);
            });
        },
        get: function Md5KeyModelGet(key, callback) {
            callback();
        },
        find: function Md5KeyModelFind(query, callback) {
            callback();
        },
        update: function Md5KeyModelUpdate(key, value, callback) {
            callback();
        },
        remove: function Md5KeyModelRemove(key, callback) {
            callback();
        }
    };

    function cloneKey(context) {
        return context.key;
    }
};