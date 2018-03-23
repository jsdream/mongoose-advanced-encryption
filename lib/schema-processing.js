'use strict';

const _ = require('lodash');
const deepFreeze = require('deep-freeze');

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

        const isBooleanOption = _.isBoolean(fieldOptions.encrypt);
        const isFieldTypeOfString = schemaType.instance === 'String';

        if (!isFieldTypeOfString && !isBooleanOption && fieldOptions.encrypt.hash && fieldOptions.encrypt.hash.index) {
            throw new Error('encrypt.hash.index option only works for String type fields');
        }

        const pathEncryptionOptions = _.defaults(isBooleanOption ? {} : fieldOptions.encrypt, pluginOptions.encrypt);

        if (!isFieldTypeOfString) {
            pathEncryptionOptions.hash.index = false;
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