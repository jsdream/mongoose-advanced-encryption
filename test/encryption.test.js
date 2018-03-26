'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;

const advancedEncryption = require('../index');

mongoose.connect('mongodb://localhost/mongoose-advanced-encryption-test');

const encryptionKey = 'GKhd2bEkC9rFpzkouE0Q1Ut4N12W94Wnwm1x7jKx4QQ=';
const hashingKey = '4eeCFsnX3QNf+Mm+2Sy6hCg1H31HEAxTjmx1vFqyfO4xYr7OhpfKargNmzCPQgObd9J1IHN9FCcy/71eyGx/zw==';
const authenticationKey = 'pt5zK3xIhhw9A/Ij31OskRNqs5pleZ30M4FwZcG59XEltRITbWPp0bP0qUS2Z2CM2+xH3d+6Y5DwRXSJzWWk4g==';

const schemaData = {
    firstName: String,
    lastName: String,
    fullName: {
        type: String,
        encrypt: {
            hash: true
        }
    },
    email: {
        type: String,
        encrypt: {
            hash: {
                index: true
            }
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
                    hash: false
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

    it('should throw an error if hashing key is not specified', function () {
        const UserSchemaWithoutHashingKey = new Schema({
            firstName: String
        });

        function attachPlugin () {
            UserSchemaWithoutHashingKey.plugin(advancedEncryption, {
                encryptionKey: encryptionKey
            });
        }

        expect(attachPlugin).to.throw('pluginOptions.hashingKey must be provided');
    });

    it('should throw an error if authentication key is not specified', function () {
        const UserSchemaWithoutEncryptionKey = new Schema({
            firstName: String
        });

        function attachPlugin () {
            UserSchemaWithoutEncryptionKey.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                hashingKey: hashingKey
            });
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
                hashingKey: hashingKey,
                authenticationKey: authenticationKey
            });
        }

        expect(attachPlugin).to.not.throw();
        expect(attachPlugin).to.throw('Mongoose Advanced Encryption plugin has been installed on this schema already');
    });
});

describe('schema processing', function () {
    it('should properly collect fields for encryption and construct their encryption options #1', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: {
                    index: false
                }
            }
        });

        const exptectedFieldsToEncrypt = {
            email: {hash: {index: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: {index: false}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should properly collect fields for encryption and construct their encryption options #2', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: {
                    index: true
                }
            }
        });

        const exptectedFieldsToEncrypt = {
            email: {hash: {index: true}},
            fullName: {hash: {index: true}},
            'secretData.creditCardNumber': {hash: {index: true}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should properly collect fields for encryption and construct their encryption options #3', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: false
            }
        });

        const exptectedFieldsToEncrypt = {
            email: {hash: {index: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: false},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should properly collect fields for encryption and construct their encryption options #4', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: true
            }
        });

        const exptectedFieldsToEncrypt = {
            email: {hash: {index: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: {index: false}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
    });

    it('should throw an error if hash option set to true for field type other than String', function () {
        const UserSchema = new Schema({
            isAdmin: {
                type: Boolean,
                encrypt: {
                    hash: {
                        index: true
                    }
                }
            }
        });

        function attachPlugin () {
            UserSchema.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                hashingKey: hashingKey,
                authenticationKey: authenticationKey,
                encrypt: {
                    hash: false
                }
            });
        }

        expect(attachPlugin).to.throw('encrypt.hash option only works for String type fields');
    });

    it('encrypt.hash option on schema/plugin level should not affect fields of non-String type', function () {
        const UserSchema = new Schema({
            isAdmin: {
                type: Boolean,
                encrypt: true
            }
        });

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: {
                    index: true
                }
            }
        });

        const expected = {
            isAdmin: {hash: false}
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
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: false
            }
        });

        function alterSchemaEncryptionOptions () {
            UserSchema.encryption.fieldsToEncrypt.email.hash = true;
        }

        expect(alterSchemaEncryptionOptions).to.throw(TypeError);
    });
    
    describe('schema augmentation', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: true
            }
        });

        it('should add cipher fields for each field to be encrypted', function () {
            expect(UserSchema.path('email_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretDataObject_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretData.creditCardNumber_c').instance).to.equal('Buffer');
            expect(UserSchema.path('secretData.details.address_c').instance).to.equal('Buffer');
        });

        it('should add hash fields for each field to be encrypted and option hash set to true', function () {
            expect(UserSchema.path('email_h').instance).to.equal('String');
            expect(UserSchema.path('fullName_h').instance).to.equal('String');
            expect(UserSchema.path('secretDataObject_h')).to.be.an('undefined');
            expect(UserSchema.path('secretData.creditCardNumber_h').instance).to.equal('String');
            expect(UserSchema.path('secretData.details.address_h')).to.be.an('undefined');
        });
    });
});

describe('encrypting/decrypting', function () {
    const UserSchema = new Schema(schemaData);

    UserSchema.plugin(advancedEncryption, {
        encryptionKey: encryptionKey,
        hashingKey: hashingKey,
        authenticationKey: authenticationKey,
        encrypt: {
            hash: {
                index: false
            }
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

            // Ensure plaintext values are removed after encryption
            expect(encrypted.email).to.be.an('undefined');
            expect(encrypted.secretDataObject).to.be.an('undefined');
            expect(encrypted.secretData.creditCardNumber).to.be.an('undefined');
            expect(encrypted.secretData.details.address).to.be.an('undefined');

            // Ensure cipher text values have been added
            expect(encrypted.email_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(encrypted.secretData.details.address_c).to.be.an.instanceof(Buffer);

            // Ensure hash values have been added
            expect(encrypted.email_h).to.have.lengthOf(88);
            expect(encrypted.fullName_h).to.be.an('undefined');
            expect(encrypted.secretDataObject_h).to.be.an('undefined');
            expect(encrypted.secretData.creditCardNumber_h).to.have.lengthOf(88);
            expect(encrypted.secretData.details.address_h).to.be.an('undefined');
        });

        it('should properly decrypt document fields when calling document.decrypt()', async function () {
            const decrypted = await user.decrypt();

            // Ensure encrypted values remain after decryption,
            // thus we can re-encrypt values only if they have been modified
            expect(decrypted.email_c).to.be.an.instanceof(Buffer);
            expect(decrypted.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(decrypted.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(decrypted.secretData.details.address_c).to.be.an.instanceof(Buffer);

            // The same goes for hashes
            expect(decrypted.email_h).to.have.lengthOf(88);
            expect(decrypted.fullName_h).to.be.an('undefined');
            expect(decrypted.secretDataObject_h).to.be.an('undefined');
            expect(decrypted.secretData.creditCardNumber_h).to.have.lengthOf(88);
            expect(decrypted.secretData.details.address_h).to.be.an('undefined');

            // Ensure values exist as plaintext after decryption
            expect(decrypted.email).to.be.a('string');
            expect(decrypted).to.have.property('secretDataObject');
            expect(decrypted).to.have.property('secretData');
            expect(decrypted.secretData.creditCardNumber).to.be.a('string');
            expect(decrypted.secretData.details.address).to.be.a('string');
        });

        it('should not encrypt paths with undefined value', async function () {
            const user = new User({
                firstName: 'John',
                lastName: 'Doe'
            });

            const encrypted = await user.encrypt();

            expect(encrypted.email_c).to.be.an('undefined');
            expect(encrypted.secretDataObject_c).to.be.an('undefined');
            expect(encrypted.secretData.creditCardNumber_c).to.be.an('undefined');
            expect(encrypted.secretData.details.address_c).to.be.an('undefined');
        });
    });

    describe('document.save()', function () {
        const userData = {
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
        };

        it('it should save encrypted data to database', async function () {
            const user = new User(userData);
            const mongooseDocument = await user.save();

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.email_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.fullName_c).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.secretData.details.address_c).to.be.an.instanceof(Buffer);

            expect(mongooseDocument.email_h).to.be.a('string');
            expect(mongooseDocument.fullName_h).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject_h).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber_h).to.be.a('string');
            expect(mongooseDocument.secretData.details.address_h).to.be.an('undefined');

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData.creditCardNumber).to.be.an('undefined');
            expect(rawRecord.secretData.address).to.be.an('undefined');

            expect(rawRecord.email_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.fullName_c).to.be.an('undefined');
            expect(rawRecord.secretDataObject_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.secretData.creditCardNumber_c.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.secretData.details.address_c.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.email_h).to.be.a('string');
            expect(rawRecord.fullName_h).to.be.an('undefined');
            expect(rawRecord.secretDataObject_h).to.be.an('undefined');
            expect(rawRecord.secretData.creditCardNumber_h).to.be.a('string');
            expect(rawRecord.secretData.details.address_h).to.be.an('undefined');
        });

        it('should create MongoDB index for fields with encrypt.hash.index === true', async function () {
            const user = new User(userData);
            await user.save();
            await User.ensureIndexes();
            const indexes = await User.collection.getIndexes();

            const expected = {
                _id_: [[ '_id', 1 ]],
                email_h_1: [[ 'email_h', 1 ]]
            };

            expect(indexes).to.deep.equal(expected);
        });

        it('should not generate deterministic ciphers', async function () {
            const user1 = new User(userData);
            const user2 = new User(userData);

            await user1.save();
            await user2.save();

            expect(user1.email_c).to.not.equal(user2.email_c);
        });

        it('should re-encrypt field only if it has changed', async function () {
            const user = new User(userData);

            await user.save();

            const encryptedValue = user.email_c;
            await user.decrypt();

            user.firstName = 'Jonathan';

            await user.save();
            const encryptedValue2 = user.email_c;
            await user.decrypt();

            user.email = 'newemail@gmail.com';

            await user.save();
            const encryptedValue3 = user.email_c;
            await user.decrypt();

            expect(encryptedValue).to.equal(encryptedValue2);
            expect(encryptedValue2).to.not.equal(encryptedValue3);
        });

        it('should remove cipher text and hash if it\'s plaintext field value was set to undefined', async function () {
            const user = new User(userData);
            await user.save();

            expect(user.email_c).to.be.an.instanceof(Buffer);
            expect(user.email_h).to.have.lengthOf(88);

            user.email = undefined;

            await user.save();

            expect(user.email).to.be.an('undefined');
            expect(user.email_c).to.be.an('undefined');
            expect(user.email_h).to.be.an('undefined');
        });

        describe('when pluginOptions.decryptAfterSave === true', function () {
            const UserSchemaDecryptAfterSave = new Schema(schemaData);

            UserSchemaDecryptAfterSave.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                hashingKey: hashingKey,
                authenticationKey: authenticationKey,
                decryptAfterSave: true
            });

            const UserDecryptAfterSave = mongoose.model('UserDecryptAfterSave', UserSchemaDecryptAfterSave);

            it('should decrypt after save', async function () {
                const user = new UserDecryptAfterSave(userData);

                const mongooseDocument = await user.save();

                expect(mongooseDocument.email_c).to.be.an.instanceof(Buffer);
                expect(mongooseDocument.fullName_c).to.be.an('undefined');
                expect(mongooseDocument.secretDataObject_c).to.be.an.instanceof(Buffer);
                expect(mongooseDocument.secretData.creditCardNumber_c).to.be.an.instanceof(Buffer);
                expect(mongooseDocument.secretData.details.address_c).to.be.an.instanceof(Buffer);

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

                await UserDecryptAfterSave.collection.drop();
            });
        });
    });

    describe('Model.find()', function () {

    });

    describe('Model.create()', function () {

    });

    afterEach(async function () {
        await User.remove({});
        await User.collection.dropIndexes();
    });
});