'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;

const advancedEncryption = require('../index');

mongoose.connect('mongodb://localhost/mongoose-advanced-encryption-test');

const encryptionKey = 'GKhd2bEkC9rFpzkouE0Q1Ut4N12W94Wnwm1x7jKx4QQ=';
const authenticationKey = 'pt5zK3xIhhw9A/Ij31OskRNqs5pleZ30M4FwZcG59XEltRITbWPp0bP0qUS2Z2CM2+xH3d+6Y5DwRXSJzWWk4g==';

const schemaData = {
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
    secretDataObject: new Schema({
        ssn: String,
        creditCardNumber: String
    }, {
        encrypt: true
    })
};

after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
});

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

    it('should throw an error on attempt to install the plugin on schema more than once', function () {
        const UserSchemaWithoutEncryptionKey = new Schema({
            firstName: String
        });

        function attachPlugin () {
            UserSchemaWithoutEncryptionKey.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                authenticationKey: authenticationKey
            });
        }

        expect(attachPlugin).to.not.throw();
        expect(attachPlugin).to.throw('Mongoose Advanced Encryption plugin has been installed on this schema already');
    });
});

describe('schema processing', function () {
    it('should read field\'s encryption options on nested and embedded documents', function () {
        const UserSchema = new Schema(schemaData);

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
            'secretData.details.address': {createBlindIndex: true},
            secretDataObject: {
                createBlindIndex: false
            }
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should throw an error if createBlindIndex set to true for field type other than String', function () {
        const UserSchema = new Schema({
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
    });
    
    describe('schema augmentation', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            authenticationKey: authenticationKey,
            encrypt: {
                createBlindIndex: true
            }
        });

        it('should add cipher fields for each field to be encrypted', function () {
            expect(UserSchema.path('email_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretDataObject_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretData.creditCardNumber_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretData.details.address_c').instance).to.equal('Buffer');
        });

        it('should add blind index fields for each field to be encrypted and option createBlindIndex set to true', function () {
            expect(UserSchema.path('email_i').instance).to.equal('String');
            expect(UserSchema.path('secretDataObject_i')).to.be.an('undefined');
            expect(UserSchema.path('secretData.creditCardNumber_i').instance).to.equal('String');
            expect(UserSchema.path('secretData.details.address_i').instance).to.equal('String');
        });
    });
});

describe('encrypting/decrypting', function () {
    const UserSchema = new Schema(schemaData);

    UserSchema.plugin(advancedEncryption, {
        encryptionKey: encryptionKey,
        authenticationKey: authenticationKey,
        encrypt: {
            createBlindIndex: false
        }
    });

    const User = mongoose.model('User', UserSchema);

    describe('document', function () {
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

        it('should properly encrypt document fields when calling document.encrypt()', async function () {
            const encrypted = await user.encrypt();

            expect(encrypted.email).to.be.an('undefined');
            expect(encrypted.secretDataObject).to.be.an('undefined');
            expect(encrypted.secretData.creditCardNumber).to.be.an('undefined');
            expect(encrypted.secretData.details.address).to.be.an('undefined');

            expect(encrypted.email_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.details.address_c).to.be.an.instanceof(Buffer);
        });

        it('should properly decrypt document fields when calling document.decrypt()', async function () {
            const decrypted = await user.decrypt();

            expect(decrypted.email_c).to.be.an('undefined');
            expect(decrypted.secretDataObject_c).to.be.an('undefined');
            expect(decrypted.secretData.creditCardNumber_c).to.be.an('undefined');
            expect(decrypted.secretData.details.address_c).to.be.an('undefined');

            expect(decrypted.email).to.be.a('string');
            expect(decrypted).to.have.property('secretDataObject');
            expect(decrypted).to.have.property('secretData');
            expect(decrypted.secretData.creditCardNumber).to.be.a('string');
            expect(decrypted.secretData.details.address).to.be.a('string');
        });
    });

    describe('document.save()', function () {
        it('it should save encrypted data to database', async function () {
            const user = new User({
                firstName: 'John',
                lastName: 'Doe',
                email: 'johndoesaved@gmail.com',
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

            const mongooseDocument = await user.save();

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.email_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.secretData.details.address_c).to.be.an.instanceof(Buffer);

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData.creditCardNumber).to.be.an('undefined');
            expect(rawRecord.secretData.address).to.be.an('undefined');

            expect(rawRecord.email_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.secretDataObject_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.secretData.creditCardNumber_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.secretData.details.address_c.buffer).to.be.an.instanceof(Buffer);
        });

        describe('with pluginOptions.decryptAfterSave set to true', function () {
            const UserSchemaDecryptAfterSave = new Schema(schemaData);

            UserSchemaDecryptAfterSave.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                authenticationKey: authenticationKey,
                decryptAfterSave: true
            });

            const UserDecryptAfterSave = mongoose.model('UserDecryptAfterSave', UserSchemaDecryptAfterSave);

            afterEach(async function () {
                await UserDecryptAfterSave.remove()
            });

            it('should decrypt after save', async function () {
                const user = new UserDecryptAfterSave({
                    firstName: 'John',
                    lastName: 'Doe',
                    email: 'johndoesaved@gmail.com',
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

                const mongooseDocument = await user.save();

                expect(mongooseDocument.email_c).to.be.an('undefined');
                expect(mongooseDocument.secretDataObject_c).to.be.an('undefined');
                expect(mongooseDocument.secretData.creditCardNumber_c).to.be.an('undefined');
                expect(mongooseDocument.secretData.details.address_c).to.be.an('undefined');

                expect(mongooseDocument.email).to.be.a('string');
                expect(mongooseDocument).to.have.property('secretDataObject');
                expect(mongooseDocument).to.have.property('secretData');
                expect(mongooseDocument.secretData.creditCardNumber).to.be.a('string');
                expect(mongooseDocument.secretData.details.address).to.be.a('string');

                const rawRecord = await UserDecryptAfterSave.collection.findOne({_id: mongooseDocument._id});

                expect(rawRecord.email).to.be.an('undefined');
                expect(rawRecord.secretDataObject).to.be.an('undefined');
                expect(rawRecord.secretData.creditCardNumber).to.be.an('undefined');
                expect(rawRecord.secretData.address).to.be.an('undefined');

                expect(rawRecord.email_c.buffer).to.be.an.instanceof(Buffer);
                expect(rawRecord.secretDataObject_c.buffer).to.be.an.instanceof(Buffer);
                expect(rawRecord.secretData.creditCardNumber_c.buffer).to.be.an.instanceof(Buffer);
                expect(rawRecord.secretData.details.address_c.buffer).to.be.an.instanceof(Buffer);
            });
        });
    });

    describe('Model.find()', function () {

    });

    describe('Model.create()', function () {

    });

    afterEach(async function () {
        await User.remove({});
    });
});