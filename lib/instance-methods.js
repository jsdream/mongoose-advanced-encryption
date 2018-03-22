'use strict';

const _ = require('lodash');
const crypto = require('./crypto');

/**
 * Attach encryption plugin instance methods.
 * @param schema
 * @param pluginOptions
 */
module.exports = function (schema, pluginOptions) {
    /**
     * Instance method to manually trigger encryption of fields marked for encryption.
     */
    schema.methods.encrypt = function () {
        const fieldsToEncrypt = schema.encryption.fieldsToEncrypt;
        const encryptionPromises = [];

        _.each(fieldsToEncrypt, (options, path) => {
            const value = _.get(this, path);
            encryptionPromises.push(crypto.encrypt(value, path, pluginOptions.encryptionKey));
        });

        return Promise.all(encryptionPromises).then((results) => {
            for (let field of results) {
                this.set(`${field.path}_c`, field.cipher);
                this.set(field.path, undefined);
            }
            return this;
        });
    };

    /**
     * Instance method to manually trigger decryption of document encrypted fields.
     */
    schema.methods.decrypt = function () {
        const fieldsToDecrypt = schema.encryption.fieldsToEncrypt;
        const decryptionPromises = [];

        _.each(fieldsToDecrypt, (options, path) => {
            decryptionPromises.push(crypto.decrypt(path, pluginOptions.encryptionKey));
        });

        return Promise.all(decryptionPromises).then((results) => {
            for (let field of results) {
                this.set(`${field.path}_c`, undefined);
                this.set(field.path, field.value);
            }
            return this;
        });
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