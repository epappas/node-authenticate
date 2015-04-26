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

module.exports = function AuthModule(config) {

    var exports = {
        events: new events.EventEmitter(),
        models: {
            acode:      require('./models/acode')(config),
            atoken:     require('./models/atoken')(config),
            aukey:      require('./models/aukey')(config),
            decision:   require('./models/decision')(config),
            md5key:     require('./models/md5key')(config),
            openkey:    require('./models/openkey')(config),
            regRef:     require('./models/regRef')(config),
            rsa:        require('./models/rsa')(config),
            salt:       require('./models/salt')(config),
            secret:     require('./models/secret')(config),
            userkey:    require('./models/userkey')(config)
        }
    };

    exports.registration = require('./lib/registration')(exports.models, exports.events, config);
    exports.auth = require('./lib/auth')(exports.models, exports.events, config);
    exports.token = require('./lib/token')(exports.models, exports.events, config);

    return exports;
};