'use strict';

const _ = require('lodash');

const config = require('./config');
const crypto = require('./crypto');

/**
 * Attach encryption plugin middleware to schema.
 * @param schema
 * @param pluginOptions
 */
module.exports = function (schema, pluginOptions) {
    schema.pre('init', function (next, data) {

    });

    schema.pre('save', function (next) {
        this.encrypt().then(() => next()).catch(next);
    });

    schema.pre('find', preFind);
    schema.pre('findOne', preFind);
    schema.pre('findOneAndRemove', preFind);
    schema.pre('findOneAndUpdate', async function () {
        preFind.call(this);
        await preUpdate.call(this);
    });
    schema.pre('count', preFind);

    function preFind () {
        const fieldsWithHash = this.schema.encryption.fieldsWithHash;
        const query = this.getQuery();

        function processQuery (query, path) {
            // Actual query alterations happen here
            if (_.has(query, path)) {
                query[path + config.HASH_FIELD_SUFFIX] = crypto.hash(_.get(query, path), pluginOptions.hashingKey);
                delete query[path];
            }

            // Recursion to support $or/$and operators
            if (_.isArray(query['$or'])) {
                for (let innerQuery of query['$or']) {
                    processQuery(innerQuery, path);
                }
            }
            if (_.isArray(query['$and'])) {
                for (let innerQuery of query['$and']) {
                    processQuery(innerQuery, path);
                }
            }
        }

        for (let path of fieldsWithHash) {
            processQuery(query, path);
        }
    }

    async function preUpdate () {
        const fieldsToEncrypt = this.schema.encryption.fieldsToEncrypt;
        const update = this.getUpdate();

        async function processUpdate (update, path, options) {
            if (_.has(update, path)) {
                const result = await crypto.encrypt(_.get(update, path), path, pluginOptions.encryptionKey);
                update[path + config.CIPHER_FIELD_SUFFIX] = result.cipher;

                if (options.hash) {
                    update[path + config.HASH_FIELD_SUFFIX] = crypto.hash(_.get(update, path), pluginOptions.hashingKey);
                }

                delete update[path];
            }
        }

        for (let path in fieldsToEncrypt) {
            await processUpdate(update, path, fieldsToEncrypt[path]);
        }
    }

    if (pluginOptions.decryptAfterSave) {
        schema.post('save', function (doc, next) {
            if (_.isFunction(doc.decrypt)) {
                doc.decrypt().then(() => next()).catch(next);
            }

            return doc;
        });
    }


};