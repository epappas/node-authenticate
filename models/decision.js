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
 * @returns {{validate: DecisionModelValidate, create: DecisionModelCreate, insert: DecisionModelInsert, get: DecisionModelGet, find: DecisionModelFind, update: DecisionModelUpdate, remove: DecisionModelRemove}}
 * @constructor
 */
module.exports = function DecisionModel(config, nano) {
    config = config || {};
    var myConfig = (config.decision = config.decision || {});

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
        _id: joi.string().alphanum().default(cloneKey),
        key: joi.string().alphanum().default(generateUuid),
        redirectUri: joi.string().uri(),
        html: joi.string().default(generateHtml),
        expires: joi.number().default(generateExpiration),
        scope: [joi.string()],
        created: joi.number().default(Date.now)
    });

    return {
        validate: function DecisionModelValidate(value, callback) {
            joi.validate(value, schema, callback);
        },
        create: function DecisionModelCreate(value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, function (err, body, headers) {
                    if (err) return callback(err);
                    callback(null, body);
                });
            });
        },
        insert: function DecisionModelInsert(key, value, callback) {
            this.validate(value, function (err, value) {
                if (err) return callback(err);
                db.insert(value, key || value.key, function (err, body, headers) {
                    if (err) return callback(err);
                    callback(null, body);
                });
            });
        },
        get: function DecisionModelGet(key, callback) {
            callback();
        },
        find: function DecisionModelFind(query, callback) {
            callback();
        },
        update: function DecisionModelUpdate(key, value, callback) {
            callback();
        },
        remove: function DecisionModelRemove(key, callback) {
            callback();
        }
    };

    function cloneKey(context) {
        return context.key;
    }

    function generateUuid() {
        return uuid.v4(uuid.v1());
    }

    function generateExpiration() {
        return Date.now() + (60 * 60 * 24 * 1000); // 1 day
    }

    function generateHtml(context) {
        return [
            '<div>',
            '<div class="header">',
            '<span class="description">',
                'Currently your are logged with id = ' + context.key,
            '</span>',
            '<span class="client">',
                'Client with id ' + context.key + ' asks for access',
            '</span>',
            '<span class="scope">',
                'Scope asked ' + context.scope.join(),
            '</span>',
            '</div>',
            '<div class="form">',
            '<form method="POST">',
            '<input type="hidden" name="decision" value="1" />',
            '<input type="submit" value="Authorize" />',
            '</form>',
            '<form method="POST">',
            '<input type="hidden" name="decision" value="0" />',
            '<input type="submit" value="Cancel" />',
            '</form>',
            '</div>'
        ].join('<br />')
    }
};