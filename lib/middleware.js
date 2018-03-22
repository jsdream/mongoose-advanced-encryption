'use strict';

const _ = require('lodash');

/**
 * Attach encryption plugin middleware to schema.
 * @param schema
 * @param options
 */
module.exports = function (schema, options) {
    schema.pre('init', function (next, data) {

    });

    schema.pre('save', function (next) {

    });

    if (options.decryptAfterSave) {
        schema.post('save', function (doc) {
            if (_.isFunction(doc.decrypt)) {
                doc.decrypt();
            }

            return doc;
        });
    }
};