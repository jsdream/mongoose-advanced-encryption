'use strict';

const _ = require('lodash');
const deepFreeze = require('deep-freeze');

const defaultFieldEncryptionOptions = {
    hash: {
        index: false
    }
};

/**
 * Export default field encryption options for use at other stages of plugin initialization.
 */
exports.defaultFieldEncryptionOptions = defaultFieldEncryptionOptions;

/**
 * Export constants
 */
exports.CIPHER_FIELD_NAME = '__enc';
exports.SIGNATURE_FIELD_NAME = '__sig';
exports.HASH_FIELD_NAME = '__hash';

/**
 * Merge default and provided options.
 * @param pluginOptions
 */
exports.mergePluginOptionsWithDefaults = function (pluginOptions) {
    _.defaultsDeep(pluginOptions, {
        decryptAfterSave: false,
        encrypt: defaultFieldEncryptionOptions
    });

    // Set hash default options if it was simply set to true
    if (pluginOptions.encrypt.hash === true) {
        pluginOptions.encrypt.hash = defaultFieldEncryptionOptions.hash;
    }

    pluginOptions.encryptionKey = new Buffer(pluginOptions.encryptionKey, 'base64');

    deepFreeze(defaultFieldEncryptionOptions);
    deepFreeze(pluginOptions.encrypt);
};

/**
 * General validation of provided plugin options.
 * @param pluginOptions
 */
exports.validatePluginOptions = function (pluginOptions) {
    if (!pluginOptions.encryptionKey) {
        throw new Error('pluginOptions.encryptionKey must be provided');
    }
    if (!pluginOptions.hashingKey) {
        throw new Error('pluginOptions.hashingKey must be provided');
    }
    if (!pluginOptions.authenticationKey) {
        throw new Error('pluginOptions.authenticationKey must be provided');
    }
};

/**
 * Validation of encryption, hashing and authentication keys.
 * @param pluginOptions
 */
exports.validateKeys = function (pluginOptions) {
    if (pluginOptions.encryptionKey.length !== 32) {
        throw new Error('pluginOptions.encryptionKey must be a 32 byte base64 string');
    }
};