'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;

const advancedEncryption = require('../index');

mongoose.connect('mongodb://localhost/mongoose-advanced-encryption-test');

const encryptionKey = 'GKhd2bEkC9rFpzkouE0Q1Ut4N12W94Wnwm1x7jKx4QQ=';
const authenticationKey = 'pt5zK3xIhhw9A/Ij31OskRNqs5pleZ30M4FwZcG59XEltRITbWPp0bP0qUS2Z2CM2+xH3d+6Y5DwRXSJzWWk4g==';

describe('mongoose-advanced-encryption plugin', function () {
    it('should throw an error if encryption key is not specified', function () {
        const UserSchemaWithoutEncryptionKey = new Schema({
            firstName: String
        });

        function attachPlugin () {
            UserSchemaWithoutEncryptionKey.plugin(advancedEncryption);
        }

        expect(attachPlugin).to.throw('pluginOptions.encryptionKey must be provided');
    });

    it('should throw an error if authentication key is not specified', function () {
        const UserSchemaWithoutEncryptionKey = new Schema({
            firstName: String
        });

        function attachPlugin () {
            UserSchemaWithoutEncryptionKey.plugin(advancedEncryption, {encryptionKey: encryptionKey});
        }

        expect(attachPlugin).to.throw('pluginOptions.authenticationKey must be provided');
    });
});

describe('schema processing', function () {
    it('should read field\'s encryption options on nested documents', function () {
        const UserSchema = new Schema({
            firstName: String,
            lastName: String,
            email: {
                type: String,
                encrypt: {
                    createBlindIndex: true
                }
            },
            secretData: {
                creditCardNumber: {
                    type: String,
                    encrypt: true
                },
                details: {
                    address: {
                        type: String,
                        encrypt: {
                            createBlindIndex: true
                        }
                    }
                }
            }
        });

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey,
            encrypt: {
                createBlindIndex: false
            }
        });

        const exptectedFieldsToEncrypt = {
            email: {createBlindIndex: true},
            'secretData.creditCardNumber': {createBlindIndex: false},
            'secretData.details.address': {createBlindIndex: true}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should read field\'s encryption options on embedded documents', function () {
        const SecretDataSchema = new Schema({
            ssn: String,
            creditCardNumber: String
        }, {
            encrypt: true
        });

        const UserSchema = new Schema({
            firstName: String,
            lastName: String,
            email: {
                type: String,
                encrypt: true
            },
            secretData: SecretDataSchema
        });

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey,
            encrypt: {
                createBlindIndex: false
            }
        });

        const expected = {
            email: {createBlindIndex: false},
            secretData: {createBlindIndex: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(expected);
    });

    it('should throw an error if createBlindIndex set to true for field type other than String', function () {
        const UserSchema = new Schema({
            firstName: String,
            lastName: String,
            isAdmin: {
                type: Boolean,
                encrypt: {
                    createBlindIndex: true
                }
            }
        });

        function attachPlugin () {
            UserSchema.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                authenticationKey: authenticationKey,
                encrypt: {
                    createBlindIndex: false
                }
            });
        }

        expect(attachPlugin).to.throw('encrypt.createBlindIndex option only works for String type fields');
    });

    it('createBlindIndex option on schema/plugin level should not affect fields of non-String type', function () {
        const UserSchema = new Schema({
            firstName: String,
            lastName: String,
            isAdmin: {
                type: Boolean,
                encrypt: true
            }
        });

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey,
            encrypt: {
                createBlindIndex: true
            }
        });

        const expected = {
            isAdmin: {createBlindIndex: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(expected);
    });

    it('should freeze schema.encryption object', function () {
        const UserSchema = new Schema({
            email: {
                type: String,
                encrypt: true
            }
        });

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey,
            encrypt: {
                createBlindIndex: false
            }
        });

        function alterSchemaEncryptionOptions () {
            UserSchema.encryption.fieldsToEncrypt.email.createBlindIndex = true;
        }

        expect(alterSchemaEncryptionOptions).to.throw(TypeError);
    })
});

describe('encrypting/decrypting', function () {
    const SecretDataSchema = new Schema({
        ssn: String,
        creditCardNumber: String
    }, {
        encrypt: true
    });

    const UserSchema = new Schema({
        firstName: String,
        lastName: String,
        email: {
            type: String,
            encrypt: {
                createBlindIndex: true
            }
        },
        secretData: {
            creditCardNumber: {
                type: String,
                encrypt: true
            },
            details: {
                address: {
                    type: String,
                    encrypt: {
                        createBlindIndex: true
                    }
                }
            }
        },
        secretDataObject: SecretDataSchema
    });

    UserSchema.plugin(advancedEncryption, {
        encryptionKey: encryptionKey,
        authenticationKey: authenticationKey,
        encrypt: {
            createBlindIndex: false
        }
    });

    const User = mongoose.model('User', UserSchema);

    const user = new User({
        firstName: 'John',
        lastName: 'Doe',
        email: 'johndoe@gmail.com',
        secretData: {
            creditCardNumber: '12334566789',
            details: {
                address: 'My address'
            }
        },
        secretDataObject: {
            ssn: '2254879844',
            creditCardNumber: '6545646545645'
        }
    });

    it('should properly encrypt document fields when calling encrypt instance method', function () {
        return user.encrypt().then((encrypted) => {
            expect(encrypted).to.not.have.own.property('email');
            expect(encrypted).to.not.have.own.property('secretDataObject');
            expect(encrypted).to.not.have.own.property('secretData.creditCardNumber');
            expect(encrypted).to.not.have.own.property('secretData.details.address');

            expect(encrypted.email_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.details.address_c).to.be.an.instanceof(Buffer);
        }, (err) => {
            console.log('err', err);
        });
    });

    it('should properly decrypt document fields when calling decrypt instance method', function () {
        return user.decrypt().then((decrypted) => {
            expect(decrypted).to.not.have.own.property('email_c');
            expect(decrypted).to.not.have.own.property('secretDataObject_c');
            expect(decrypted).to.not.have.own.property('secretData.creditCardNumber_c');
            expect(decrypted).to.not.have.own.property('secretData.details.address_c');

            expect(decrypted.email).to.be.an.instanceof(String);
            expect(decrypted).to.have.own.property('secretDataObject');
            expect(decrypted).to.have.own.property('secretData.creditCardNumber');
            expect(decrypted).to.have.own.property('secretData.details.address');
        }, (err) => {
            console.log('err', err);
        });
    });
});