var joi = require('joi');
var should = require('should');
var authenticate = require('../index')({
    models: {
        acode:      {dbPath: 'auth_acode'},
        atoken:     {dbPath: 'auth_atoken'},
        aukey:      {dbPath: 'auth_aukey'},
        decision:   {dbPath: 'auth_decision'},
        md5key:     {dbPath: 'auth_md5key'},
        openkey:    {dbPath: 'auth_openkey'},
        regref:     {dbPath: 'auth_regref'},
        rsa:        {dbPath: 'auth_rsa'},
        salt:       {dbPath: 'auth_salt'},
        secret:     {dbPath: 'auth_secret'},
        userkey:    {dbPath: 'auth_userkey'}
    }
});

describe('Registration', function () {
    var registration = new authenticate.registration();
    var regEmail = 'test_{{rand}}@example.com'.replace('{{rand}}', Math.random().toString(16).slice(2));

    it('Should Create a user account', function (done) {
        registration.register(regEmail, function (err, result) {
            should(err).be.empty;

            should.exist(result);

            var regResp = joi.object().keys({
                _id: joi.string(),
                _rev: joi.string(),
                relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                scope: joi.array().items(joi.string()).required(),
                expires: joi.number().required(),
                created: joi.number().required(),
                state: {
                    _id: joi.string(),
                    _rev: joi.string(),
                    email: joi.string().email().required(),
                    token: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    salt: joi.string().required(),
                    relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    expires: joi.number().required(),
                    scope: joi.array().items(joi.string()).required()
                }
            });

            regResp.validate(result, function(err, result) {
                should(err).be.empty;
                should.exist(result);
                done();
            });
        });
    });
});