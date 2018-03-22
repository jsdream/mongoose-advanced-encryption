'use strict';

const _ = require('lodash');
const deepFreeze = require('deep-freeze');

const attachMiddleware = require('./middleware');
const attachInstanceMethods = require('./instance-methods');

const ENCRYPTION_ALGORITHM = 'aes-256-cbc';

module.exports = function mongooseEncryptionPlugin (schema, pluginOptions = {}) {
    const defaultFieldEncryptionOptions = {
        createBlindIndex: false
    };

    schema.encryption = {
        fieldsToEncrypt: {}
    };

    _.defaultsDeep(pluginOptions, {
        decryptAfterSave: true,
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
     * Iterate through each schema path and collect fields to be encrypted and their encryption options.
     * Also extend field specific encryption options with default encryption options. 
     */
    schema.eachPath((path, schemaType) => {
        const fieldOptions = schemaType.instance === 'Embedded' ? schemaType.schema.options : schemaType.options;
        
        if (!fieldOptions.encrypt) {
            return;
        }

        const isBooleanOption = _.isBoolean(fieldOptions.encrypt);
        const isFieldTypeOfString = schemaType.instance === 'String';

        if (!isFieldTypeOfString && !isBooleanOption && fieldOptions.encrypt.createBlindIndex) {
            throw new Error('encrypt.createBlindIndex option only works for String type fields');
        }

        schema.encryption.fieldsToEncrypt[path] =  _.defaults(isBooleanOption ? {} : fieldOptions.encrypt, pluginOptions.encrypt);

        if (!isFieldTypeOfString) {
            schema.encryption.fieldsToEncrypt[path].createBlindIndex = false;
        }

        schema.add({
            [`${path}_c`]: {
                type: Buffer
            }
        });
    });

    deepFreeze(schema.encryption);

    /**
     * Middleware
     */
    attachMiddleware(schema, pluginOptions);

    /**
     * Instance methods
     */
    attachInstanceMethods(schema, pluginOptions);
};