'use strict';

const config = require('./config');
const attachMiddleware = require('./middleware');
const attachInstanceMethods = require('./instance-methods');
const processSchema = require('./schema-processing');

module.exports = function mongooseEncryptionPlugin (schema, pluginOptions = {}) {
    if (schema.encryption) {
        throw new Error('Mongoose Advanced Encryption plugin has been installed on this schema already');
    }
    
    schema.encryption = {
        fieldsToEncrypt: {}
    };

    /**
     * Plugin options processing
     */
    config.validatePluginOptions(pluginOptions);
    config.mergePluginOptionsWithDefaults(pluginOptions);
    config.validateKeys(pluginOptions);

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