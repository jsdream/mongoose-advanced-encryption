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
                    const hashValue = _.isUndefined(value) ? undefined : crypto.computeHMAC(value, pluginOptions.hashingKey, 'base64');
                    this.set(`${config.HASH_FIELD_NAME}.${path}`, hashValue);
                }
            }

            this.set(path, undefined);
        });

        if (isDataModified) {
            this[config.CIPHER_FIELD_NAME] = await crypto.encrypt(dataToEncrypt, pluginOptions.encryptionKey);
            this.sign();
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
    schema.methods.sign = function (document = this) {
        const dataToSign = this.getDataToSign.call(this, document);
        const HMAC = crypto.computeHMAC(dataToSign, pluginOptions.authenticationKey);

        this[config.SIGNATURE_FIELD_NAME] = Buffer.concat([config.VERSION_BUFFER, HMAC]);

        return this;
    };

    /**
     * Instance method to authenticate signed fields.
     */
    schema.methods.authenticate = function (document = this) {
        const signature = document[config.SIGNATURE_FIELD_NAME];
        
        if (!signature) {
            throw new Error('Document signature is missing');
        }
        
        const actualSignatureBuffer = signature.hasOwnProperty('buffer') ? signature.buffer : signature;
        const dataToVerify = this.getDataToSign.call(this, document);
        const HMAC = crypto.computeHMAC(dataToVerify, pluginOptions.authenticationKey);
        const expectedSignatureBuffer = Buffer.concat([config.VERSION_BUFFER, HMAC]);

        if (!expectedSignatureBuffer.equals(actualSignatureBuffer)) {
            throw new Error('Document signature authentication failed');
        }
    };

    /**
     * Returns document's data which should be signed.
     */
    schema.methods.getDataToSign = function (document = this) {
        const cipher = document[config.CIPHER_FIELD_NAME];

        return {
            _id: document._id,
            collectionName: this.collection.collectionName,
            [config.CIPHER_FIELD_NAME]: cipher.hasOwnProperty('buffer') ? cipher.buffer : cipher
        };
    };
};