'use strict';

const _ = require('lodash');
const deepFreeze = require('deep-freeze');

const config = require('./config');

/**
 * Iterate through each schema path and collect fields to be encrypted and their encryption options.
 * Also extend field specific encryption options with default encryption options.
 * @param schema
 * @param pluginOptions
 */
module.exports = function (schema, pluginOptions) {
    const hashFieldSchemaType = {};

    schema.eachPath((path, schemaType) => {
        const schemaTypeOptions = schemaType.instance === 'Embedded' ? schemaType.schema.options : schemaType.options;

        if (!schemaTypeOptions.encrypt) {
            return;
        }
        
        config.validateSchemaTypeOptions(path, schemaTypeOptions);

        const isEncryptBooleanOption = _.isBoolean(schemaTypeOptions.encrypt);
        const isFieldTypeOfString = schemaType.instance === 'String';

        if (!isFieldTypeOfString && !isEncryptBooleanOption && schemaTypeOptions.encrypt.hash) {
            throw new Error('encrypt.hash option only works for String type fields');
        }

        const pathEncryptionOptions = _.defaults({}, isEncryptBooleanOption ? {} : schemaTypeOptions.encrypt, pluginOptions.encrypt);

        if (pathEncryptionOptions.hash === true) {
            pathEncryptionOptions.hash = pluginOptions.encrypt.hash ? pluginOptions.encrypt.hash : config.defaultFieldEncryptionOptions.hash;
        }

        if (!isFieldTypeOfString) {
            pathEncryptionOptions.hash = false;
        }

        if (pathEncryptionOptions.hash) {
            const pathSchemaType = {
                type: String
            };

            if (pathEncryptionOptions.hash.index) {
                pathSchemaType.index = pathEncryptionOptions.hash.index;
            }
            if (pathEncryptionOptions.hash.unique) {
                pathSchemaType.unique = pathEncryptionOptions.hash.unique;
            }
            if (pathEncryptionOptions.hash.sparse) {
                pathSchemaType.sparse = pathEncryptionOptions.hash.sparse;
            }

            hashFieldSchemaType[path] = pathSchemaType;
        }

        schema.encryption.fieldsToEncrypt[path] = pathEncryptionOptions;
    });

    /**
     * Augment schema
     */
    schema.add({
        [config.CIPHER_FIELD_NAME]: {
            type: Buffer
        },
        [config.SIGNATURE_FIELD_NAME]: {
            type: Buffer
        },
        [config.HASH_FIELD_NAME]: hashFieldSchemaType
    });

    schema.encryption.fieldsWithHash = _.reduce(schema.encryption.fieldsToEncrypt, (array, options, path) => {
        if (options.hash) {
            array.push(path);
        }
        return array;
    }, []);

    deepFreeze(schema.encryption);
};