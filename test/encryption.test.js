'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const expect = require('chai').expect;

const advancedEncryption = require('../index');

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
    username: {
        type: String,
        encrypt: {
            hash: {
                index: true
            }
        }
    },
    email: {
        type: String,
        encrypt: {
            hash: {
                unique: true
            }
        }
    },
    mainSkill: {
        type: String,
        encrypt: {
            hash: {
                sparse: true
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

const userData = {
    firstName: 'John',
    lastName: 'Doe',
    username: 'johndoe',
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

before(async () => {
    await mongoose.connect('mongodb://localhost/mongoose-advanced-encryption-test', {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false});
});

after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
});

describe('[mongoose-advanced-encryption plugin]', function () {
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

describe('[schema processing]', function () {
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

        const expectedFieldsToEncrypt = {
            username: {hash: {index: true}},
            email: {hash: {unique: true}},
            mainSkill: {hash: {sparse: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: {index: false}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        const expectedFieldsWithHash = ['username', 'email', 'mainSkill', 'fullName', 'secretData.creditCardNumber'];

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(expectedFieldsToEncrypt);
        expect(UserSchema.encryption.fieldsWithHash).to.have.members(expectedFieldsWithHash);
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
            username: {hash: {index: true}},
            email: {hash: {unique: true}},
            mainSkill: {hash: {sparse: true}},
            fullName: {hash: {index: true}},
            'secretData.creditCardNumber': {hash: {index: true}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        const expectedFieldsWithHash = ['username', 'email', 'mainSkill', 'fullName', 'secretData.creditCardNumber'];

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
        expect(UserSchema.encryption.fieldsWithHash).to.have.members(expectedFieldsWithHash);
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
            username: {hash: {index: true}},
            email: {hash: {unique: true}},
            mainSkill: {hash: {sparse: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: false},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        const expectedFieldsWithHash = ['username', 'email', 'mainSkill', 'fullName'];

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
        expect(UserSchema.encryption.fieldsWithHash).to.have.members(expectedFieldsWithHash);
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
            username: {hash: {index: true}},
            email: {hash: {unique: true}},
            mainSkill: {hash: {sparse: true}},
            fullName: {hash: {index: false}},
            'secretData.creditCardNumber': {hash: {index: false}},
            'secretData.details.address': {hash: false},
            secretDataObject: {hash: false}
        };

        const expectedFieldsWithHash = ['username', 'email', 'mainSkill', 'fullName', 'secretData.creditCardNumber'];

        expect(UserSchema.encryption.fieldsToEncrypt).to.deep.equal(exptectedFieldsToEncrypt);
        expect(UserSchema.encryption.fieldsWithHash).to.have.members(expectedFieldsWithHash);
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

    it('should throw an error if index option was set for encrypted field', function () {
        const UserSchema = new Schema({
            email: {
                type: String,
                index: true,
                encrypt: true
            }
        });

        function attachPlugin () {
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
        }

        expect(attachPlugin).to.throw(
            'SchemaType "index" option on encrypted path "email" is not supported. ' +
            'It should be specified as "encrypt.hash.index" SchemaType option instead.'
        );
    });

    it('should throw an error if unique option was set for encrypted field', function () {
        const UserSchema = new Schema({
            email: {
                type: String,
                unique: true,
                encrypt: true
            }
        });

        function attachPlugin () {
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
        }

        expect(attachPlugin).to.throw(
            'SchemaType "unique" option on encrypted path "email" is not supported. ' +
            'It should be specified as "encrypt.hash.unique" SchemaType option instead.'
        );
    });

    it('should throw an error if sparse option was set for encrypted field', function () {
        const UserSchema = new Schema({
            email: {
                type: String,
                sparse: true,
                encrypt: true
            }
        });

        function attachPlugin () {
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
        }

        expect(attachPlugin).to.throw(
            'SchemaType "sparse" option on encrypted path "email" is not supported. ' +
            'It should be specified as "encrypt.hash.sparse" SchemaType option instead.'
        );
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

    describe('* schema augmentation', function () {
        const UserSchema = new Schema(schemaData);

        UserSchema.plugin(advancedEncryption, {
            encryptionKey: encryptionKey,
            hashingKey: hashingKey,
            authenticationKey: authenticationKey,
            encrypt: {
                hash: true
            }
        });

        it('should add cipher and signature fields to schema', function () {
            expect(UserSchema.path('__enc').instance).to.equal('Buffer');
            expect(UserSchema.path('__sig').instance).to.equal('Buffer');
        });

        it('should add hash fields for each field to be encrypted and option hash set to true', function () {
            expect(UserSchema.path('__hash.email').instance).to.equal('String');
            expect(UserSchema.path('__hash.fullName').instance).to.equal('String');
            expect(UserSchema.path('__hash.secretDataObject')).to.be.an('undefined');
            expect(UserSchema.path('__hash.secretData.creditCardNumber').instance).to.equal('String');
            expect(UserSchema.path('__hash.secretData.details.address')).to.be.an('undefined');
        });
    });
});

describe('[encrypting/decrypting]', async function () {
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

    describe('* document', function () {
        it('should properly encrypt document fields when calling document.encEncrypt()', async function () {
            const user = new User(userData);
            const encrypted = await user.encEncrypt();

            // Ensure plaintext values are removed after encryption
            expect(encrypted.email).to.be.an('undefined');
            expect(encrypted.secretDataObject).to.be.an('undefined');
            expect(encrypted.secretData.creditCardNumber).to.be.an('undefined');
            expect(encrypted.secretData.details.address).to.be.an('undefined');

            // Ensure cipher text and signature values have been added
            expect(encrypted.__enc).to.be.an.instanceof(Buffer);
            expect(encrypted.__sig).to.be.an.instanceof(Buffer);

            // Ensure hash values have been added
            expect(encrypted.__hash).to.not.be.an('undefined');
            expect(encrypted.__hash.email).to.have.lengthOf(88);
            expect(encrypted.__hash.fullName).to.be.an('undefined');
            expect(encrypted.__hash.secretDataObject).to.be.an('undefined');
            expect(encrypted.__hash.secretData.creditCardNumber).to.have.lengthOf(88);
            expect(encrypted.__hash.secretData.details).to.be.an('undefined');
        });

        it('should properly decrypt document fields when calling document.encDecrypt()', async function () {
            const user = new User(userData);
            const encrypted = await user.encEncrypt();
            const decrypted = await encrypted.encDecrypt();

            expect(decrypted.__enc).to.be.an.instanceof(Buffer);
            expect(decrypted.__sig).to.be.an.instanceof(Buffer);

            expect(decrypted.__hash.email).to.have.lengthOf(88);
            expect(decrypted.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

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

            const encrypted = await user.encEncrypt();

            expect(encrypted).to.not.have.own.property('__hash');
            expect(encrypted.__enc).to.be.an('undefined');
            expect(encrypted.__sig).to.be.an('undefined');
        });


        it('should not encrypt already encrypted document', async function () {
            const user = new User(userData);
            const encrypted = await user.encEncrypt();
            const encrypted2 = await encrypted.encEncrypt();

            const decrypted = await encrypted2.encDecrypt();

            expect(decrypted.__enc).to.be.an.instanceof(Buffer);
            expect(decrypted.__sig).to.be.an.instanceof(Buffer);

            expect(decrypted.__hash.email).to.have.lengthOf(88);
            expect(decrypted.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

            // Ensure values exist as plaintext after decryption
            expect(decrypted.email).to.be.a('string');
            expect(decrypted).to.have.property('secretDataObject');
            expect(decrypted).to.have.property('secretData');
            expect(decrypted.secretData.creditCardNumber).to.be.a('string');
            expect(decrypted.secretData.details.address).to.be.a('string');
        });
    });

    describe('* document.save()', function () {
        it('it should save encrypted data to database', async function () {
            const user = new User(userData);
            const mongooseDocument = await user.save();

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.__enc).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.__sig).to.be.an.instanceof(Buffer);

            expect(mongooseDocument.__hash.email).to.be.a('string');
            expect(mongooseDocument.__hash.fullName).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretData.creditCardNumber).to.be.a('string');
            expect(mongooseDocument.__hash.secretData.details).to.be.an('undefined');

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData).to.be.an('undefined');

            expect(rawRecord.__enc.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.__sig.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.__hash.email).to.be.a('string');
            expect(rawRecord.__hash.fullName).to.be.an('undefined');
            expect(rawRecord.__hash.secretDataObject).to.be.an('undefined');
            expect(rawRecord.__hash.secretData.creditCardNumber).to.be.a('string');
            expect(rawRecord.__hash.secretData.details).to.be.an('undefined');
        });

        it('should properly create MongoDB indexes', async function () {
            const user = new User(userData);
            await user.save();
            await User.createIndexes({background: false});
            const indexes = await User.collection.indexInformation({full: true});

            const expected = [
                {
                    v: 2,
                    key: {_id: 1},
                    name: '_id_',
                },
                {
                    v: 2,
                    key: {'__hash.username': 1},
                    name: '__hash.username_1',
                    background: false
                },
                {
                    v: 2,
                    unique: true,
                    key: {'__hash.email': 1},
                    name: '__hash.email_1',
                    background: false
                },
                {
                    v: 2,
                    key: {'__hash.mainSkill': 1},
                    name: '__hash.mainSkill_1',
                    sparse: true,
                    background: false
                }
            ];

            expect(indexes).to.deep.equal(expected);
        });

        it('should not generate deterministic ciphers', async function () {
            const user1 = new User(userData);
            const user2 = new User(userData);

            await user1.save();
            await user2.save();

            expect(user1.__enc).to.not.equal(user2.__enc);
        });

        it('should re-encrypt fields only if at least one of encrypted fields has changed', async function () {
            const user = new User(userData);

            await user.save();

            const encryptedValue = user.__enc;
            await user.encDecrypt();

            user.firstName = 'Jonathan';

            await user.save();

            const encryptedValue2 = user.__enc;
            await user.encDecrypt();

            user.email = 'newemail@gmail.com';

            await user.save();
            const encryptedValue3 = user.__enc;
            await user.encDecrypt();

            expect(encryptedValue).to.equal(encryptedValue2);
            expect(encryptedValue).to.not.equal(encryptedValue3);
        });

        it('should remove encrypted value if it\'s plaintext field value was set to undefined', async function () {
            const user = new User(userData);
            await user.save();
            await user.encDecrypt();

            expect(user.__enc).to.be.an.instanceof(Buffer);
            expect(user.__hash.email).to.have.lengthOf(88);

            user.email = undefined;

            await user.save();

            const user2 = await User.findOne({_id: user._id}).exec();

            expect(user2.email).to.be.an('undefined');
        });

        it('should remove hash if it\'s plaintext field value was set to undefined', async function () {
            const user = new User(userData);
            await user.save();
            await user.encDecrypt();

            expect(user.__enc).to.be.an.instanceof(Buffer);
            expect(user.__hash.email).to.have.lengthOf(88);

            user.email = undefined;

            await user.save();

            expect(user.__hash.email).to.be.an('undefined');

            const decrypted = await User.findOne({_id: user._id}).exec();

            expect(decrypted.__hash.email).to.be.an('undefined');
        });

        it('should decrypt after save when pluginOptions.decryptAfterSave === true', async function () {
            const UserSchemaDecryptAfterSave = new Schema(schemaData);

            UserSchemaDecryptAfterSave.plugin(advancedEncryption, {
                encryptionKey: encryptionKey,
                hashingKey: hashingKey,
                authenticationKey: authenticationKey,
                decryptAfterSave: true
            });

            const UserDecryptAfterSave = mongoose.model('UserDecryptAfterSave', UserSchemaDecryptAfterSave);

            const user = new UserDecryptAfterSave(userData);

            const mongooseDocument = await user.save();

            expect(mongooseDocument.email).to.be.a('string');
            expect(mongooseDocument).to.have.property('secretDataObject');
            expect(mongooseDocument).to.have.property('secretData');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.a('string');
            expect(mongooseDocument.secretData.details.address).to.be.a('string');

            const rawRecord = await UserDecryptAfterSave.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData).to.be.an('undefined');

            expect(rawRecord.__enc.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.__sig.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.__hash.email).to.be.a('string');
            expect(rawRecord.__hash.secretData.creditCardNumber).to.be.a('string');

            await UserDecryptAfterSave.collection.drop();
        });
    });

    describe('* Model.update()', function () {
        it('should throw an error when attempting to update encrypted fields', async function () {
            const mongooseDocument = new User({email: 'emptyuser@gmail.com'});
            await mongooseDocument.save();

            let error;

            try {
                await User.update({email: 'emptyuser@gmail.com'}, userData).exec();
            }
            catch (err) {
                error = err;
            }

            expect(error).to.be.an('error');
            expect(error.message).to.equal('Can not perform partial update of encrypted fields');
        });

        it('it should throw an error when attempting to update encrypted fields #2', async function () {
            const mongooseDocument = new User({email: 'emptyuser@gmail.com'});
            await mongooseDocument.save();

            let error;

            try {
                await User.update({email: 'emptyuser@gmail.com'}, {$set: {email: 'updated@gmail.com'}}).exec();
            }
            catch (err) {
                error = err;
            }

            expect(error).to.be.an('error');
            expect(error.message).to.equal('Can not perform partial update of encrypted fields');
        });

        it('it should perform an update when there are no encrypted fields in update', async function () {
            const mongooseDocument = new User({email: 'emptyuser@gmail.com'});
            await mongooseDocument.save();

            let error;
            let result;

            try {
                result = await User.update({email: 'emptyuser@gmail.com'}, {firstName: 'John'}).exec();
            }
            catch (err) {
                error = err;
            }

            expect(result).to.eql({n: 1, nModified: 1, ok: 1});
            expect(error).to.be.an('undefined');
        });
    });

    describe('* Model.create()', function () {
        it('it should save encrypted data to database', async function () {
            const mongooseDocument = await User.create(userData);

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.__enc).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.__sig).to.be.an.instanceof(Buffer);

            expect(mongooseDocument.__hash.email).to.be.a('string');
            expect(mongooseDocument.__hash.fullName).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretData.creditCardNumber).to.be.a('string');
            expect(mongooseDocument.__hash.secretData.details).to.be.an('undefined');

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData).to.be.an('undefined');

            expect(rawRecord.__enc.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.__sig.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.__hash.email).to.be.a('string');
            expect(rawRecord.__hash.secretData.creditCardNumber).to.be.a('string');
        });
    });

    describe('* Model.insertMany()', function () {
        it('it should throw an error #1', async function () {
            let error;

            try {
                await User.insertMany(userData);
            }
            catch (err) {
                error = err;
            }

            expect(error).to.be.an('error');
            expect(error.message).to.equal('insertMany method can only be used with mongoose documents, but not plain objects');
        });

        it('it should throw an error #2', async function () {
            let error;

            try {
                await User.insertMany([userData, userData, userData]);
            }
            catch (err) {
                error = err;
            }

            expect(error).to.be.an('error');
            expect(error.message).to.equal('insertMany method can only be used with mongoose documents, but not plain objects');
        });

        it('it should save encrypted data to database #1', async function () {
            const results = await User.insertMany(new User(userData));

            const mongooseDocument = results[0];

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.__enc).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.__sig).to.be.an.instanceof(Buffer);

            expect(mongooseDocument.__hash.email).to.be.a('string');
            expect(mongooseDocument.__hash.fullName).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretData.creditCardNumber).to.be.a('string');
            expect(mongooseDocument.__hash.secretData.details).to.be.an('undefined');

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData).to.be.an('undefined');

            expect(rawRecord.__enc.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.__sig.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.__hash.email).to.be.a('string');
            expect(rawRecord.__hash.secretData.creditCardNumber).to.be.a('string');
        });

        it('it should save encrypted data to database #2', async function () {
            const results = await User.insertMany([new User(userData), new User(userData), new User(userData)]);

            const mongooseDocument = results[0];

            expect(mongooseDocument.email).to.be.an('undefined');
            expect(mongooseDocument.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.secretData.creditCardNumber).to.be.an('undefined');
            expect(mongooseDocument.secretData.address).to.be.an('undefined');

            expect(mongooseDocument.__enc).to.be.an.instanceof(Buffer);
            expect(mongooseDocument.__sig).to.be.an.instanceof(Buffer);

            expect(mongooseDocument.__hash.email).to.be.a('string');
            expect(mongooseDocument.__hash.fullName).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretDataObject).to.be.an('undefined');
            expect(mongooseDocument.__hash.secretData.creditCardNumber).to.be.a('string');
            expect(mongooseDocument.__hash.secretData.details).to.be.an('undefined');

            const rawRecord = await User.collection.findOne({_id: mongooseDocument._id});

            expect(rawRecord.email).to.be.an('undefined');
            expect(rawRecord.secretDataObject).to.be.an('undefined');
            expect(rawRecord.secretData).to.be.an('undefined');

            expect(rawRecord.__enc.buffer).to.be.an.instanceof(Buffer);
            expect(rawRecord.__sig.buffer).to.be.an.instanceof(Buffer);

            expect(rawRecord.__hash.email).to.be.a('string');
            expect(rawRecord.__hash.secretData.creditCardNumber).to.be.a('string');
        });
    });

    afterEach(async function () {
        await User.deleteMany({});

        try {
            await User.collection.dropIndexes({background: false});
        }
        catch (err) {}
    });
});

describe('[Querying encrypted documents]', function () {
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

    const User = mongoose.model('UserQuery', UserSchema);

    describe('(should be able to query by full-match against encrypted fields which utilizing blind index)', function () {
        beforeEach(async function () {
            const user = new User(userData);
            await user.save();
        });

        const query1 = {email: userData.email};
        const query2 = {'secretData.creditCardNumber': userData.secretData.creditCardNumber};
        const query3 = {email: userData.email, 'secretData.creditCardNumber': userData.secretData.creditCardNumber};
        const query4 = {
            $or: [
                {firstName: 'BadName'},
                {email: userData.email}
            ]
        };
        const query5 = {
            $and: [
                {firstName: 'John'},
                {email: userData.email}
            ]
        };
        const query6 = {
            $and: [
                {
                    $or: [
                        {email: 'wrong'},
                        {email: userData.email}
                    ]
                },
                {
                    firstName: 'John'
                }
            ]
        };

        describe('* Model.find()', function () {
            it('query #1-6', async function () {
                const result1 = await User.find(query1).exec();
                expect(result1).to.have.lengthOf(1);

                const result2 = await User.find(query2).exec();
                expect(result2).to.have.lengthOf(1);

                const result3 = await User.find(query3).exec();
                expect(result3).to.have.lengthOf(1);

                const result4 = await User.find(query4).exec();
                expect(result4).to.have.lengthOf(1);

                const result5 = await User.find(query5).exec();
                expect(result5).to.have.lengthOf(1);

                const result6 = await User.find(query6).exec();
                expect(result6).to.have.lengthOf(1);
            });

            it('should return decrypted documents', async function () {
                const result = await User.find(query1).exec();
                const user = result[0];

                expect(user.__enc).to.be.an.instanceof(Buffer);
                expect(user.__sig).to.be.an.instanceof(Buffer);

                expect(user.__hash.email).to.have.lengthOf(88);
                expect(user.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

                // Ensure values exist as plaintext after decryption
                expect(user.email).to.be.a('string');
                expect(user).to.have.property('secretDataObject');
                expect(user).to.have.property('secretData');
                expect(user.secretData.creditCardNumber).to.be.a('string');
                expect(user.secretData.details.address).to.be.a('string');
            });
        });

        describe('* Model.findOne()', function () {
            it('query #1-6', async function () {
                const result1 = await User.findOne(query1).exec();
                expect(result1.firstName).to.be.a('string');

                const result2 = await User.findOne(query2).exec();
                expect(result2.firstName).to.be.a('string');

                const result3 = await User.findOne(query3).exec();
                expect(result3.firstName).to.be.a('string');

                const result4 = await User.findOne(query4).exec();
                expect(result4.firstName).to.be.a('string');

                const result5 = await User.findOne(query5).exec();
                expect(result5.firstName).to.be.a('string');

                const result6 = await User.findOne(query6).exec();
                expect(result6.firstName).to.be.a('string');
            });

            it('should return decrypted documents', async function () {
                const user = await User.findOne(query1).exec();

                expect(user.__enc).to.be.an.instanceof(Buffer);
                expect(user.__sig).to.be.an.instanceof(Buffer);

                expect(user.__hash.email).to.have.lengthOf(88);
                expect(user.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

                // Ensure values exist as plaintext after decryption
                expect(user.email).to.be.a('string');
                expect(user).to.have.property('secretDataObject');
                expect(user).to.have.property('secretData');
                expect(user.secretData.creditCardNumber).to.be.a('string');
                expect(user.secretData.details.address).to.be.a('string');
            });
        });

        describe('* Model.count()', function () {
            it('query #1-6', async function () {
                const result1 = await User.count(query1).exec();
                expect(result1).to.equal(1);

                const result2 = await User.count(query2).exec();
                expect(result2).to.equal(1);

                const result3 = await User.count(query3).exec();
                expect(result3).to.equal(1);

                const result4 = await User.count(query4).exec();
                expect(result4).to.equal(1);

                const result5 = await User.count(query5).exec();
                expect(result5).to.equal(1);

                const result6 = await User.count(query6).exec();
                expect(result6).to.equal(1);
            });
        });

        describe('* Model.countDocuments()', function () {
            it('query #1-6', async function () {
                const result1 = await User.countDocuments(query1).exec();
                expect(result1).to.equal(1);

                const result2 = await User.countDocuments(query2).exec();
                expect(result2).to.equal(1);

                const result3 = await User.countDocuments(query3).exec();
                expect(result3).to.equal(1);

                const result4 = await User.countDocuments(query4).exec();
                expect(result4).to.equal(1);

                const result5 = await User.countDocuments(query5).exec();
                expect(result5).to.equal(1);

                const result6 = await User.countDocuments(query6).exec();
                expect(result6).to.equal(1);
            });
        });

        describe('* Model.findOneAndRemove()', function () {
            it('query #1', async function () {
                const result1 = await User.findOneAndRemove(query1).exec();
                expect(result1.firstName).to.be.a('string');
            });

            it('query #2', async function () {
                const result2 = await User.findOneAndRemove(query2).exec();
                expect(result2.firstName).to.be.a('string');
            });

            it('query #3', async function () {
                const result3 = await User.findOneAndRemove(query3).exec();
                expect(result3.firstName).to.be.a('string');
            });

            it('query #4', async function () {
                const result4 = await User.findOneAndRemove(query4).exec();
                expect(result4.firstName).to.be.a('string');
            });

            it('query #5', async function () {
                const result5 = await User.findOneAndRemove(query5).exec();
                expect(result5.firstName).to.be.a('string');
            });

            it('query #6', async function () {
                const result6 = await User.findOneAndRemove(query6).exec();
                expect(result6.firstName).to.be.a('string');
            });

            it('should return decrypted documents', async function () {
                const user = await User.findOneAndRemove(query1).exec();

                expect(user.__enc).to.be.an.instanceof(Buffer);
                expect(user.__sig).to.be.an.instanceof(Buffer);

                expect(user.__hash.email).to.have.lengthOf(88);
                expect(user.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

                // Ensure values exist as plaintext after decryption
                expect(user.email).to.be.a('string');
                expect(user).to.have.property('secretDataObject');
                expect(user).to.have.property('secretData');
                expect(user.secretData.creditCardNumber).to.be.a('string');
                expect(user.secretData.details.address).to.be.a('string');
            });
        });

        describe('* Model.findOneAndUpdate()', function () {
            it('it should throw an error when attempting to update encrypted fields', async function () {
                const update = {
                    email: 'updatedemail@gmail.com',
                    'secretData.details.address': '123'
                };

                let error;

                try {
                    await User.findOneAndUpdate(query1, update).exec();
                }
                catch (err) {
                    error = err;
                }

                expect(error).to.be.an('error');
                expect(error.message).to.equal('Can not perform partial update of encrypted fields');
            });

            it('it should perform an update when there are no encrypted fields in update', async function () {
                const find1 = await User.findOneAndUpdate(query4, {firstName: 'John2'}).exec();
                const find2 = await User.findOne({firstName: 'John2'}).exec();

                expect(find1.firstName).to.equal('John');
                expect(find2.firstName).to.equal('John2');
            });

            it('should return decrypted documents', async function () {
                const user = await User.findOneAndUpdate(query4, {firstName: 'John2'}).exec();

                expect(user.__enc).to.be.an.instanceof(Buffer);
                expect(user.__sig).to.be.an.instanceof(Buffer);

                expect(user.__hash.email).to.have.lengthOf(88);
                expect(user.__hash.secretData.creditCardNumber).to.have.lengthOf(88);

                // Ensure values exist as plaintext after decryption
                expect(user.email).to.be.a('string');
                expect(user).to.have.property('secretDataObject');
                expect(user).to.have.property('secretData');
                expect(user.secretData.creditCardNumber).to.be.a('string');
                expect(user.secretData.details.address).to.be.a('string');
            });
        });
    });

    afterEach(async function () {
        await User.deleteMany({});
        await User.collection.dropIndexes();
    });
});

describe('[Authentication]', function () {
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

    const User = mongoose.model('UserAuth', UserSchema);
    const User2 = mongoose.model('UserAuth2', UserSchema);

    it('should pass authentication if all authentication fields are selected', async function () {
        await User.create(userData);

        let user;
        let error;

        try {
            user = await User.findOne({email: userData.email}).exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
        expect(user).to.have.property('email');
    });

    it('should pass authentication if none of authentication fields are selected', async function () {
        await User.create(userData);

        let user;
        let error;

        try {
            user = await User.findOne({email: userData.email}).select('firstName lastName').exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
        expect(user.firstName).to.equal('John');
        expect(user.lastName).to.equal('Doe');
        expect(user.email).to.be.an('undefined');
    });

    it('should pass authentication if none of authentication fields are selected #2', async function () {
        await User.create(userData);

        let user;
        let error;

        try {
            user = await User.findOne({email: userData.email}).select('firstName lastName -_id').exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
        expect(user._id).to.be.an('undefined');
        expect(user.firstName).to.equal('John');
        expect(user.lastName).to.equal('Doe');
    });

    it('should fail authentication if not all authentication fields are selected', async function () {
        await User.create(userData);

        let user;
        let error;

        try {
            user = await User.findOne({email: userData.email}).select('firstName lastName __enc -_id').exec();
        }
        catch (err) {
            error = err;
        }

        expect(user).to.be.an('undefined');
        expect(error).to.be.an('error');
        expect(error.message).to.equal('Document signature authentication failed. Either all or none authentication fields must be selected.');
    });

    it('should fail authentication if document _id has changed', async function () {
        const user1 = await User.create(userData);
        const user2 = await User.create({email: 'seconduser@gmail.com'});

        await User.collection.update({_id: user2._id}, {$set: {__enc: user1.__enc, __sig: user1.__sig}});

        let error;

        try {
            await User.findOne({_id: user2._id}).exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('error');
        expect(error.message).to.equal('Document signature authentication failed');
    });

    it('should fail authentication if collection name has changed', async function () {
        const user1 = await User.create(userData);
        const user2 = await User2.create({_id: user1._id, email: 'seconduser@gmail.com'});

        await User2.collection.update({_id: user2._id}, {$set: {__enc: user1.__enc, __sig: user1.__sig}});

        let error;

        try {
            await User2.findOne({_id: user2._id}).exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('error');
        expect(error.message).to.equal('Document signature authentication failed');
    });

    it('should not perform authentication if document has no cipher', async function () {
        const user = await User.create({firstName: 'John', lastName: 'Doe'});

        let error;
        let user2;

        try {
            user2 = await User.findOne({_id: user._id}).exec();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
        expect(user2.firstName).to.be.equal('John');
        expect(user2.lastName).to.be.equal('Doe');
    });

    afterEach(async function () {
        await User.deleteMany({});
        await User2.deleteMany({});
        await User.collection.dropIndexes();
        await User2.collection.dropIndexes();
    });
});

describe('Validation', function () {
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

    const User = mongoose.model('UserValidation', UserSchema);

    it('should successfully pass document validation', async function () {
        const user = await User.create(userData);

        let error;

        try {
            await user.validate();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
    });

    it('should successfully pass document validation #2', async function () {
        await User.create(userData);
        const user = await User.findOne({email: userData.email}).select('firstName lastName').exec();


        let error;

        try {
            await user.validate();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
    });

    it('should successfully pass document validation on save', async function () {
        await User.create(userData);
        const user = await User.findOne({email: userData.email}).select('firstName lastName').exec();


        let error;

        try {
            await user.save();
        }
        catch (err) {
            error = err;
        }

        expect(error).to.be.an('undefined');
    });

    afterEach(async function () {
        await User.deleteMany({});
        await User.collection.dropIndexes();
    });
});
