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

var Boom = require('boom');

/**
 *
 * @param self
 * @param models
 * @param events
 * @param config
 * @returns {register}
 * @constructor
 */
module.exports = (function BearerPlugin (self, models, events, config) {
    'use strict';

    var validation = new self.validation();

    var register = function register(plugin, options, next) {
        plugin.auth.scheme('bearer', bearerValidation);
        next();
    };

    register.attributes = {
        pkg: require('../package.json')
    };

    return register;

    function bearerValidation(server, options) {

        return {
            authenticate: function authenticate(request, reply) {
                var req = request.raw.req;
                var authorization = req.headers.authorization;

                // { realm: 'something', error: 'invalid_token' error_description: 'The access token expired' }

                if (!authorization)
                    return reply(Boom.unauthorized(
                        'Missing Header',
                        'bearer',
                        {realm: 'atoken', error: 'missing_token', error_description: 'Missing Bearer Authentication Header' }
                    ));

                var parts = authorization.split(/\s+/);

                if (parts[0].toLowerCase() !== 'bearer')
                    return reply(Boom.unauthorized(
                        'Wrong Header',
                        'bearer',
                        {realm: 'atoken', error: 'wrong_header', error_description: 'Wrong authorization header'}
                    ));

                var token = parts[1];
                var scope = (request.query.scope || '').split(',');
                var uniqueKey = request.headers['x-unique-key'] || request.query.uniqueKey || null;

                validation.validate({
                    accessToken: token,
                    uniqueKey: uniqueKey,
                    scope: scope
                }, function (err, atoken) {
                    if (err)
                        return reply(Boom.forbidden(
                            'Validation issue',
                            'bearer',
                            {realm: 'atoken', error: 'bad_validation', error_description: 'Validation issue', data: err}
                        ));
                    if (!atoken)
                        return reply(Boom.forbidden(
                            'Validation issue',
                            'bearer',
                            {realm: 'atoken', error: 'bad_validation', error_description: 'Validation token issue', data: [token, scope, uniqueKey]}
                        ));

                    return reply.continue({
                        credentials: {atoken: atoken}
                    });
                });
            }
        };
    }

});
