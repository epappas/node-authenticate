var joi = require('joi');
var async = require('async');
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

describe('User - Domain accounts', function () {
    var registration = new authenticate.registration();
    var validation = new authenticate.validation();
    var auth = new authenticate.auth();
    var token = new authenticate.token();

    var regEmail = 'test_{{rand}}@example.com'.replace('{{rand}}', Math.random().toString(16).slice(2));
    var regRef;
    var tokenState;
    var myAtoken;
    var myAukey;
    var myOpenkey;
    var myUserkey;
    var myAukeySecret;
    var myOpenkeySecret;
    var myUserkey;

    describe('Should registration create vitals', function () {
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
                    uniqueKey: joi.string(), // .required(),
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

        it('Should have valid atoken', function (done) {
            authenticate.models.atoken.get(tokenState.token, function (err, atoken) {
                should(err).be.empty;

                should.exist(atoken);

                var atokenSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    salt: joi.string().required(),
                    uniqueKey: joi.string(), // .required(),
                    expires: joi.number().required(),
                    created: joi.number().required(),
                    scope: joi.array().items(joi.string()).required()
                });

                atokenSchema.validate(atoken, function (err, atoken) {
                    should(err).be.empty;
                    should.exist(atoken);

                    myAtoken = atoken;

                    done();
                });
            });
        });

        it('Should have valid aukey', function (done) {
            authenticate.models.aukey.get(myAtoken.relkey, function (err, aukey) {
                should(err).be.empty;

                should.exist(aukey);

                var aukeySchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    relkey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    scope: joi.array().items(joi.string()).required(),
                    created: joi.number().required()
                });

                aukeySchema.validate(aukey, function (err, aukey) {
                    should(err).be.empty;
                    should.exist(aukey);

                    myAukey = aukey;

                    done();
                });
            });
        });

        it('Should have valid openkey', function (done) {
            authenticate.models.openkey.get(myAukey.relkey, function (err, openkey) {
                should(err).be.empty;

                should.exist(openkey);

                var openkeySchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    ukey: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    relkey: joi.string().required(),
                    scope: joi.array().items(joi.string()).required(),
                    created: joi.number().required()
                });

                openkeySchema.validate(openkey, function (err, openkey) {
                    should(err).be.empty;
                    should.exist(openkey);

                    myOpenkey = openkey;

                    done();
                });
            });
        });

        it('Should have valid userkey', function (done) {
            authenticate.models.userkey.get(myOpenkey.ukey, function (err, userkey) {
                should(err).be.empty;

                should.exist(userkey);

                var userkeySchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    email: joi.string().email().required(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    alias: joi.array().items(joi.string().email()),
                    created: joi.number().required()
                });

                userkeySchema.validate(userkey, function (err, userkey) {
                    should(err).be.empty;
                    should.exist(userkey);

                    should(userkey.email).be.equal(regEmail);

                    myUserkey = userkey;

                    done();
                });
            });
        });
    });

    describe('Should registration create Security essentials', function () {

        it('Should have valid aukey secrets', function (done) {
            authenticate.models.secret.get(myAukey.key, function (err, aukeySecret) {
                should(err).be.empty;

                should.exist(aukeySecret);

                var aukeySecretSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    verifier: joi.string().required(),
                    srpsalt: joi.string().required(),
                    created: joi.number().required()
                });

                aukeySecretSchema.validate(aukeySecret, function (err, aukeySecret) {
                    should(err).be.empty;
                    should.exist(aukeySecret);

                    myAukeySecret = aukeySecret;

                    done();
                });
            });
        });

        it('Should have valid aukey rsa', function (done) {
            authenticate.models.rsa.get(myAukey.key, function (err, rsa) {
                should(err).be.empty;

                should.exist(rsa);

                var rsaSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    rsaPrivKey: joi.string().allow(''),
                    rsaBits: joi.any().required(),
                    created: joi.number().required()
                });

                rsaSchema.validate(rsa, function (err, rsa) {
                    should(err).be.empty;
                    should.exist(rsa);

                    done();
                });
            });
        });

        it('Should have valid openkey secrets', function (done) {
            authenticate.models.secret.get(myOpenkey.key, function (err, openkeySecret) {
                should(err).be.empty;

                should.exist(openkeySecret);

                var openkeySecretSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    verifier: joi.string().required(),
                    srpsalt: joi.string().required(),
                    created: joi.number().required()
                });

                openkeySecretSchema.validate(openkeySecret, function (err, openkeySecret) {
                    should(err).be.empty;
                    should.exist(openkeySecret);

                    myOpenkeySecret = openkeySecret;

                    done();
                });
            });
        });

        it('Should have valid openkey rsa', function (done) {
            authenticate.models.rsa.get(myOpenkey.key, function (err, rsa) {
                should(err).be.empty;

                should.exist(rsa);

                var rsaSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    rsaPrivKey: joi.string().allow(''),
                    rsaBits: joi.any().required(),
                    created: joi.number().required()
                });

                rsaSchema.validate(rsa, function (err, rsa) {
                    should(err).be.empty;
                    should.exist(rsa);

                    done();
                });
            });
        });

        it('Should have valid userkey secrets', function (done) {
            authenticate.models.secret.get(myUserkey.key, function (err, userkeySecret) {
                should(err).be.empty;

                should.exist(userkeySecret);

                var userkeySecretSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    verifier: joi.string().required(),
                    srpsalt: joi.string().required(),
                    created: joi.number().required()
                });

                userkeySecretSchema.validate(userkeySecret, function (err, userkeySecret) {
                    should(err).be.empty;
                    should.exist(userkeySecret);

                    myUserkeySecret = userkeySecret;

                    done();
                });
            });
        });

        it('Should have valid userkey rsa', function (done) {
            authenticate.models.rsa.get(myUserkey.key, function (err, rsa) {
                should(err).be.empty;

                should.exist(rsa);

                var rsaSchema = joi.object().keys({
                    _id: joi.string(),
                    _rev: joi.string(),
                    key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                    rsaPrivKey: joi.string().allow(''),
                    rsaBits: joi.any().required(),
                    created: joi.number().required()
                });

                rsaSchema.validate(rsa, function (err, rsa) {
                    should(err).be.empty;
                    should.exist(rsa);

                    done();
                });
            });
        });
    });

    describe('OAUTH 2', function () {

        describe('CODE Flow', function () {
            var myDecision;
            var myCode;
            var myNewAtoken;

            it('Should request login via auth', function (done) {
                auth.authenticate({
                    method: 'GET',
                    redirectUri: '/',
                    apiKey: myAukey.key,
                    // secret: myAukeySecret.verifier,
                    responseType: 'code', // or token
                    scope: ['test'],
                    state: {gameSession: 1234},
                    userSession: {}
                }, function (err, decision) {
                    should(err).be.empty;
                    should.exist(decision);

                    var decisionSchema = joi.object().keys({
                        _id: joi.string(),
                        _rev: joi.string(),
                        key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                        scope: joi.array().items(joi.string()).required(),
                        html: joi.string().required(),
                        state: joi.any(),
                        expires: joi.number().required(),
                        created: joi.number().required()
                    });

                    decisionSchema.validate(decision, function (err, decision) {
                        should(err).be.empty;
                        should.exist(decision);

                        myDecision = decision;

                        done();
                    });
                });
            });

            it('Should accept the request and issue an AUTH CODE', function (done) {
                auth.authenticate({
                    method: 'POST',
                    redirectUri: '/',
                    apiKey: myAukey.key,
                    secret: myAukeySecret.verifier,
                    responseType: 'code', // or token
                    scope: ['test'],
                    state: {gameSession: 1234},
                    userSession: {},
                    decision: 1
                }, function (err, code) {
                    should(err).be.empty;
                    should.exist(code);

                    var codeSchema = joi.object().keys({
                        _id: joi.string(),
                        _rev: joi.string(),
                        key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                        scope: joi.array().items(joi.string()).required(),
                        relkey: joi.string(),
                        code: joi.string().required(),
                        state: joi.any(),
                        internalState: joi.any(),
                        expires: joi.number().required(),
                        created: joi.number().required()
                    });

                    codeSchema.validate(code, function (err, code) {
                        should(err).be.empty;
                        should.exist(code);

                        myCode = code;

                        done();
                    });
                });
            });

            it('Should use AUTH CODE to request a token', function (done) {
                token.authenticate({
                    grantType: 'authorization_code',
                    redirectUri: '/',
                    apiKey: myAukey.key,
                    secret: myAukeySecret.verifier,
                    code: myCode.key,
                    scope: ['test'],
                    state: {gameSession: 1234}
                }, function (err, atoken) {
                    should(err).be.empty;
                    should.exist(atoken);

                    var atokenSchema = joi.object().keys({
                        state: joi.any(),
                        token_type: joi.string().valid('bearer'),
                        access_token: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                        expires_in: joi.number().required(),
                        expires: joi.number().required()
                    });

                    atokenSchema.validate(atoken, function (err, atoken) {
                        should(err).be.empty;
                        should.exist(atoken);

                        myNewAtoken = atoken;
                        done();
                    });
                });
            });
        });

        describe('IMPLICIT Flow', function () {
            var myDecision;
            var myCode;
            var myNewAtoken;

            it('Should request login via auth', function (done) {
                auth.authenticate({
                    method: 'GET',
                    redirectUri: '/',
                    apiKey: myAukey.key,
                    responseType: 'token',
                    scope: ['test'],
                    state: {gameSession: 1234},
                    userSession: {}
                }, function (err, decision) {
                    should(err).be.empty;
                    should.exist(decision);

                    var decisionSchema = joi.object().keys({
                        _id: joi.string(),
                        _rev: joi.string(),
                        key: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                        scope: joi.array().items(joi.string()).required(),
                        html: joi.string().required(),
                        state: joi.any(),
                        expires: joi.number().required(),
                        created: joi.number().required()
                    });

                    decisionSchema.validate(decision, function (err, decision) {
                        should(err).be.empty;
                        should.exist(decision);

                        myDecision = decision;

                        done();
                    });
                });
            });

            it('Should accept the request and issue an AUTH CODE', function (done) {
                auth.authenticate({
                    method: 'POST',
                    redirectUri: '/',
                    apiKey: myAukey.key,
                    responseType: 'token',
                    scope: ['test'],
                    state: {gameSession: 1234},
                    userSession: {},
                    decision: 1
                }, function (err, atoken) {
                    should(err).be.empty;
                    should.exist(atoken);

                    var atokenSchema = joi.object().keys({
                        access_token: joi.string().regex(/[a-zA-Z0-9\-]+/).required(),
                        uniqueKey: joi.string(), // .required(),
                        salt: joi.string(),
                        state: joi.any(),
                        expires: joi.number().required(),
                        expires_in: joi.number().required()
                    });

                    atokenSchema.validate(atoken, function (err, atoken) {
                        should(err).be.empty;
                        should.exist(atoken);

                        done();
                    });
                });
            });
        });
    });
});