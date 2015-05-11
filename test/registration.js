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
    var validation = new authenticate.validation();

    var regEmail = 'test_{{rand}}@example.com'.replace('{{rand}}', Math.random().toString(16).slice(2));
    var regRef;

    it('Should Create a user account', function (done) {
        registration.newUser(regEmail, function (err, result) {
            should(err).be.empty;

            should.exist(result);

            var regRespSchema = joi.object().keys({
                _id: joi.string(),
                _rev: joi.string(),
                relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                scope: joi.array().items(joi.string()).required(),
                expires: joi.number().required(),
                created: joi.number().required(),
                status: joi.string().valid('pending', 'fulfilled', 'paused', 'error', 'expired', 'cancelled'),
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

            regRespSchema.validate(result, function (err, result) {
                should(err).be.empty;
                should.exist(result);
                regRef = result;
                done();
            });
        });
    });

    it('Should get the created registration state', function (done) {

        registration.get(regRef.key, function (err, regState) {
            should(err).be.empty;

            should.exist(regState);

            var regRespSchema = joi.object().keys({
                _id: joi.string(),
                _rev: joi.string(),
                email: joi.string().email().required(),
                token: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                salt: joi.string().required(),
                relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                expires: joi.number().required(),
                scope: joi.array().items(joi.string()).required()
            });

            regRespSchema.validate(regState, function (err, regState) {
                should(err).be.empty;
                should.exist(regState);

                tokenState = regState;

                done();
            });
        });
    });

    it('Should validate the fetched token', function (done) {
        validation.validate({
            accessToken: tokenState.token,
            uniqueKey: tokenState.relkey,
            scope: tokenState.scope
        }, function (err, atoken) {
            should(err).be.empty;

            should.exist(atoken);

            var atokenSchema = joi.object().keys({
                _id: joi.string(),
                _rev: joi.string(),
                key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                salt: joi.string().required(),
                uniqueKey: joi.string().required(),
                relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                expires: joi.number().required(),
                created: joi.number().required(),
                scope: joi.array().items(joi.string()).required()
            });

            atokenSchema.validate(atoken, function (err, atoken) {
                should(err).be.empty;
                should.exist(atoken);

                done();
            });
        });
    });
});