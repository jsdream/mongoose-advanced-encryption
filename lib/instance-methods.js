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
        const dataToEncrypt = {};

        let isDataModified = false;

        _.each(fieldsToEncrypt, (options, path) => {
            const value = this.get(path);

            _.set(dataToEncrypt, path, value);

            if (this.isModified(path)) {
                isDataModified = true;

                if (options.hash) {
                    const hashValue = _.isUndefined(value) ? undefined : crypto.hash(value, pluginOptions.hashingKey);
                    this.set(`${config.HASH_FIELD_NAME}.${path}`, hashValue);
                }
            }

            this.set(path, undefined);
        });

        if (isDataModified) {
            this[config.CIPHER_FIELD_NAME] = await crypto.encrypt(dataToEncrypt, pluginOptions.encryptionKey);
        }

        return this;
    };

    /**
     * Instance method to manually trigger decryption of document encrypted fields.
     */
    schema.methods.decrypt = function (document = this) {
        const encrypted = document[config.CIPHER_FIELD_NAME];

        if (encrypted) {
            const cipher = encrypted.hasOwnProperty('buffer') ? encrypted.buffer : encrypted;
            const decrypted = crypto.decrypt(cipher, pluginOptions.encryptionKey);

            _.merge(document, decrypted);

            for (let path in this.schema.encryption.fieldsToEncrypt) {
                this.unmarkModified(path);
            }
        }

        return document;
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