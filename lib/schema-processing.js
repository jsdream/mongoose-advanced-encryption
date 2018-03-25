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
    schema.eachPath((path, schemaType) => {
        const fieldOptions = schemaType.instance === 'Embedded' ? schemaType.schema.options : schemaType.options;

        if (!fieldOptions.encrypt) {
            return;
        }

        const isEncryptBooleanOption = _.isBoolean(fieldOptions.encrypt);
        const isFieldTypeOfString = schemaType.instance === 'String';

        if (!isFieldTypeOfString && !isEncryptBooleanOption && fieldOptions.encrypt.hash) {
            throw new Error('encrypt.hash option only works for String type fields');
        }

        const pathEncryptionOptions = _.defaults({}, isEncryptBooleanOption ? {} : fieldOptions.encrypt, pluginOptions.encrypt);

        if (pathEncryptionOptions.hash === true) {
            pathEncryptionOptions.hash = pluginOptions.encrypt.hash ? pluginOptions.encrypt.hash : config.defaultFieldEncryptionOptions.hash;
        }

        if (!isFieldTypeOfString) {
            pathEncryptionOptions.hash = false;
        }

        /**
         * Augment schema
         */
        schema.add({
            [`${path}_c`]: {
                type: Buffer
            }
        });

        if (pathEncryptionOptions.hash) {
            schema.add({
                [`${path}_h`]: {
                    type: String,
                    index: pathEncryptionOptions.hash.index
                }
            });
        }

        schema.encryption.fieldsToEncrypt[path] = pathEncryptionOptions;
    });

    deepFreeze(schema.encryption);
};