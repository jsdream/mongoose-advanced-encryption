'use strict';

const _ = require('lodash');
const crypto = require('./crypto');

const CIPHER_FIELD_SUFFIX = '_c';

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

        _.each(fieldsToEncrypt, (options, path) => {
            const value = this.get(path);
            encryptionPromises.push(crypto.encrypt(value, path, pluginOptions.encryptionKey));
        });

        const results = await Promise.all(encryptionPromises);

        for (let field of results) {
            this.set(field.path + CIPHER_FIELD_SUFFIX, field.cipher);
            this.set(field.path, undefined);
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
            const cipherText = this.get(path + CIPHER_FIELD_SUFFIX);
            decryptionPromises.push(crypto.decrypt(cipherText, path, pluginOptions.encryptionKey));
        });

        const results = await Promise.all(decryptionPromises);

        for (let field of results) {
            this.set(field.path + CIPHER_FIELD_SUFFIX, undefined);
            this.set(field.path, field.value);
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