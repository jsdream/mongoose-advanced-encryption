'use strict';

const _ = require('lodash');
const mongoose = require('mongoose');

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
    schema.methods.encEncrypt = async function () {
        /**
         * Prevents re-encrypting encrypted documents.
         */
        if (this[config.ENCRYPTION_STATUS_FIELD_NAME] === config.DOCUMENT_ENCRYPTION_STATUSES.ENCRYPTED) {
            return this;
        }

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
            this[config.ENCRYPTION_STATUS_FIELD_NAME] = config.DOCUMENT_ENCRYPTION_STATUSES.ENCRYPTED;
            this.encSign();
        }

        return this;
    };

    /**
     * Instance method to manually trigger decryption of document encrypted fields.
     */
    schema.methods.encDecrypt = function (document = this) {
        const encrypted = document[config.CIPHER_FIELD_NAME];

        if (encrypted) {
            const cipher = encrypted.hasOwnProperty('buffer') ? encrypted.buffer : encrypted;
            const decrypted = crypto.decrypt(cipher, pluginOptions.encryptionKey);

            _.merge(document, decrypted);

            for (let path in this.schema.encryption.fieldsToEncrypt) {
                this.unmarkModified(path);
            }

            document[config.ENCRYPTION_STATUS_FIELD_NAME] = config.DOCUMENT_ENCRYPTION_STATUSES.DECRYPTED;
        }

        return document;
    };

    /**
     * Instance method to manually sign fields.
     */
    schema.methods.encSign = function (document = this) {
        const dataToSign = this.encGetDataToSign.call(this, document);
        const HMAC = crypto.computeHMAC(dataToSign, pluginOptions.authenticationKey);

        this[config.SIGNATURE_FIELD_NAME] = Buffer.concat([config.VERSION_BUFFER, HMAC]);

        return this;
    };

    /**
     * Instance method to authenticate signed fields.
     */
    schema.methods.encAuthenticate = function (document = this) {
        const signature = document[config.SIGNATURE_FIELD_NAME];
        const cipher = document[config.CIPHER_FIELD_NAME];

        const selectionStatus = this.encGetAuthenticationFieldsSelectionStatus();

        if (selectionStatus === config.FIELDS_SELECTION_STATUSES.NONE) {
            return;
        }
        if (selectionStatus === config.FIELDS_SELECTION_STATUSES.SOME) {
            throw new Error('Document signature authentication failed. Either all or none authentication fields must be selected.');
        }
        if (!signature) {
            if (pluginOptions.skipAuthenticationIfNoSignature || !cipher) {
                return;
            }

            throw new Error('Document signature is missing');
        }

        const actualSignatureBuffer = signature.hasOwnProperty('buffer') ? signature.buffer : signature;
        const dataToVerify = this.encGetDataToSign.call(this, document);
        const HMAC = crypto.computeHMAC(dataToVerify, pluginOptions.authenticationKey);
        const expectedSignatureBuffer = Buffer.concat([config.VERSION_BUFFER, HMAC]);

        if (!expectedSignatureBuffer.equals(actualSignatureBuffer)) {
            throw new Error('Document signature authentication failed');
        }
    };

    /**
     * Returns document's data which should be signed.
     */
    schema.methods.encGetDataToSign = function (document = this) {
        const cipher = document[config.CIPHER_FIELD_NAME];

        return {
            _id: document._id,
            collectionName: this.collection.collectionName,
            [config.CIPHER_FIELD_NAME]: cipher.hasOwnProperty('buffer') ? cipher.buffer : cipher
        };
    };

    schema.methods.encGetAuthenticatedFields = function () {
        return [config.CIPHER_FIELD_NAME];
    };

    schema.methods.encGetAuthenticationFieldsSelectionStatus = function () {
        const authFieldsSelectionStatus = _.map(this.encGetAuthenticatedFields(), (fieldName) => {
            return this.isSelected(fieldName);
        });

        if (_.uniq(authFieldsSelectionStatus).length !== 1) {
            return config.FIELDS_SELECTION_STATUSES.SOME;
        }
        else if (authFieldsSelectionStatus[0] === true) {
            if (this.isSelected('_id')) {
                return config.FIELDS_SELECTION_STATUSES.ALL;
            }
            else {
                return config.FIELDS_SELECTION_STATUSES.SOME;
            }
        }
        else if (authFieldsSelectionStatus[0] === false) {
            return config.FIELDS_SELECTION_STATUSES.NONE;
        }
    };

    /**
     * Override toJSON
     */
    const toJSON = mongoose.Document.prototype.toJSON;

    schema.methods.toJSON = function (/* options, ... */) {
        const ret = toJSON.call(this, ...arguments);

        /**
         * Delete cipher, signature and hash fields from resulting json.
         */
        delete ret[config.CIPHER_FIELD_NAME];
        delete ret[config.SIGNATURE_FIELD_NAME];
        delete ret[config.HASH_FIELD_NAME];

        return ret;
    };
};
