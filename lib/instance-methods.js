'use strict';

const _ = require('lodash');

const crypto = require('./crypto');
const config = require('./config');

/**
 * Attach encryption plugin instance methods.
 * @param schema
 * @param pluginOptions
 */
module.exports = function (schema, pluginOptions) {
    /**
     * Instance method to manually trigger encryption of fields marked for encryption.
     */
    schema.methods.encrypt = async function () {
        const fieldsToEncrypt = schema.encryption.fieldsToEncrypt;
        const encryptionPromises = [];
        const hashingResults = [];

        _.each(fieldsToEncrypt, (options, path) => {
            const value = this.get(path);
            const cipherValue = this.get(path + config.CIPHER_FIELD_SUFFIX);

            // Remove cipher and hash if their plaintext field was removed
            if (_.isUndefined(value) && !_.isUndefined(cipherValue)) {
                this.set(path + config.CIPHER_FIELD_SUFFIX, undefined);
                this.set(path + config.HASH_FIELD_SUFFIX, undefined);
            }
            // Encrypt field only if it was modified
            else if (this.isModified(path)) {
                encryptionPromises.push(crypto.encrypt(value, path, pluginOptions.encryptionKey));

                if (options.hash) {
                    hashingResults.push({
                        hash: crypto.hash(value, pluginOptions.hashingKey),
                        path: path
                    });
                }
            }
        });

        const encryptedFields = await Promise.all(encryptionPromises);

        for (let field of encryptedFields) {
            this.set(field.path + config.CIPHER_FIELD_SUFFIX, field.cipher);
            this.set(field.path, undefined);
        }

        for (let field of hashingResults) {
            this.set(field.path + config.HASH_FIELD_SUFFIX, field.hash);
        }

        return this;
    };

    /**
     * Instance method to manually trigger decryption of document encrypted fields.
     */
    schema.methods.decrypt = async function () {
        const fieldsToDecrypt = schema.encryption.fieldsToEncrypt;
        const decryptionPromises = [];

        _.each(fieldsToDecrypt, (options, path) => {
            const cipherText = this.get(path + config.CIPHER_FIELD_SUFFIX);
            if (!_.isUndefined(cipherText)) {
                decryptionPromises.push(crypto.decrypt(cipherText, path, pluginOptions.encryptionKey));
            }
        });

        const results = await Promise.all(decryptionPromises);

        for (let field of results) {
            this.set(field.path, field.value);
            this.unmarkModified(field.path);
        }

        return this;
    };

    /**
     * Instance method to manually sign fields.
     */
    schema.methods.sign = function () {

    };

    /**
     * Instance method to authenticate signed fields.
     */
    schema.methods.authenticate = function () {

    };
};