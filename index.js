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

var events = require('events');

module.exports = function AuthModule(config) {
    config = config || {};
    config.nano = config.nano || require('nano')('http://localhost:5984');

    var exports = {
        events: new events.EventEmitter(),
        models: {
            acode:      require('./models/acode')(config.models, config.nano),
            atoken:     require('./models/atoken')(config.models, config.nano),
            aukey:      require('./models/aukey')(config.models, config.nano),
            decision:   require('./models/decision')(config.models, config.nano),
            md5key:     require('./models/md5key')(config.models, config.nano),
            openkey:    require('./models/openkey')(config.models, config.nano),
            regref:     require('./models/regref')(config.models, config.nano),
            rsa:        require('./models/rsa')(config.models, config.nano),
            salt:       require('./models/salt')(config.models, config.nano),
            secret:     require('./models/secret')(config.models, config.nano),
            userkey:    require('./models/userkey')(config.models, config.nano)
        }
    };

    exports.registration    = require('./lib/registration')(exports.models, exports.events, config.registration);
    exports.auth            = require('./lib/auth')(exports.models, exports.events, config.auth);
    exports.token           = require('./lib/token')(exports.models, exports.events, config.token);

    return exports;
};