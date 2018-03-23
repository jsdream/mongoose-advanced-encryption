'use strict';

const _ = require('lodash');

const attachMiddleware = require('./middleware');
const attachInstanceMethods = require('./instance-methods');
const processSchema = require('./schema-processing');

module.exports = function mongooseEncryptionPlugin (schema, pluginOptions = {}) {
    if (schema.encryption) {
        throw new Error('Mongoose Advanced Encryption plugin has been installed on this schema already');
    }

    const defaultFieldEncryptionOptions = {
        hash: {
            index: false
        }
    };

    schema.encryption = {
        fieldsToEncrypt: {}
    };

    _.defaultsDeep(pluginOptions, {
        decryptAfterSave: false,
        encrypt: defaultFieldEncryptionOptions
    });

    /**
     * Validate Options
     */
    if (!pluginOptions.encryptionKey) {
        throw new Error('pluginOptions.encryptionKey must be provided');
    }
    if (!pluginOptions.authenticationKey) {
        throw new Error('pluginOptions.authenticationKey must be provided');
    }

    pluginOptions.encryptionKey = new Buffer(pluginOptions.encryptionKey, 'base64');

    if (pluginOptions.encryptionKey.length !== 32) {
        throw new Error('pluginOptions.encryptionKey must be a 32 byte base64 string');
    }

    /**
     * Schema processing
     */
    processSchema(schema, pluginOptions);

    /**
     * Middleware
     */
    attachMiddleware(schema, pluginOptions);

    /**
     * Instance methods
     */
    attachInstanceMethods(schema, pluginOptions);
};