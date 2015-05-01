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

describe('Auth AUKEY', function () {
    var registration = new authenticate.registration();
    var auth = new authenticate.auth();
    var regEmail = 'test_{{rand}}@example.com'.replace('{{rand}}', Math.random().toString(16).slice(2));
    var tokenState;
    var aukeyState;
    var secretState;

    before(function(done) {
        registration.register(regEmail, function (err, result) {
            should(err).be.empty;
            should.exist(result);

            registration.get(result.key, function (err, regState) {
                should(err).be.empty;
                should.exist(regState);

                tokenState = regState;
                authenticate.models.aukey.get(tokenState.relkey, function (err, aukey) {
                    should(err).be.empty;
                    should.exist(aukey);

                    aukeyState = aukey;

                    authenticate.models.secret.get(aukey.key, function (err, secret) {
                        should(err).be.empty;
                        should.exist(secret);

                        secretState = secret;

                        done();
                    });
                });
            });
        });
    });

    it('Should authenticate and respond with access code', function (done) {
        auth.authenticate({
            method: 'GET',
            redirectUri: '/',
            apiKey: aukeyState.key,
            secret: secretState.verifier,
            responseType: 'code', // or token
            scope: tokenState.scope,
            state: {test: 1234},
            decision: true
        }, function (err, acode) {
            should(err).be.empty;
            should.exist(acode);

            console.log(err, acode);

            done();
        });
    });

    it('Should authenticate and respond with access token', function (done) {
        auth.authenticate({
            method: 'GET',
            redirectUri: '/',
            apiKey: aukeyState.key,
            secret: secretState.verifier,
            responseType: 'token', // or token
            scope: tokenState.scope,
            state: {test: 1234},
            decision: true
        }, function (err, atoken) {
            should(err).be.empty;
            should.exist(atoken);

            console.log(err, atoken);

            done();
        });
    });
});