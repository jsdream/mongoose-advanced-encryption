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
        this.encrypt().then(() => next()).catch(next);
    });

    if (options.decryptAfterSave) {
        schema.post('save', function (doc, next) {
            if (_.isFunction(doc.decrypt)) {
                doc.decrypt().then(() => next()).catch(next);
            }

            return doc;
        });
    }
};