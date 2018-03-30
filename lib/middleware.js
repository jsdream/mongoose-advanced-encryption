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
    /**
     * Register middleware
     */
    schema.pre('init', function (doc) {
        this.decrypt.call(this, doc);
    });

    schema.pre('save', async function () {
        await this.encrypt();
    });

    schema.pre('update', async function () {
        preUpdate.call(this);
        preFind.call(this);
    });

    schema.pre('insertMany', async function () {
        console.log('this', this);
    });

    schema.pre('find', preFind);
    schema.pre('findOne', preFind);
    schema.pre('findOneAndRemove', preFind);
    schema.pre('findOneAndUpdate', async function () {
        preFind.call(this);
        await preUpdate.call(this);
    });
    schema.pre('count', preFind);

    /**
     * Functions
     */
    function preFind () {
        const fieldsWithHash = this.schema.encryption.fieldsWithHash;
        const query = this.getQuery();

        function processQuery (query, path) {
            // Actual query alterations happen here
            if (_.has(query, path)) {
                query[`${config.HASH_FIELD_NAME}.${path}`] = crypto.hash(_.get(query, path), pluginOptions.hashingKey);
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

    function preUpdate () {
        const fieldsToEncrypt = this.schema.encryption.fieldsToEncrypt;
        const update = this.getUpdate();

        function processUpdate (update, path) {
            if (_.has(update, path)) {
                throw new Error('Can not perform partial update of encrypted fields');
            }

            const updateOperators = ['$set', '$unset'];

            // Recursion to support update operators
            for (let operator of updateOperators) {
                if (_.isObject(update[operator])) {
                    processUpdate(update[operator], path);
                }
            }
        }

        for (let path in fieldsToEncrypt) {
            processUpdate(update, path);
        }
    }

    if (pluginOptions.decryptAfterSave) {
        schema.post('save', function (doc) {
            if (_.isFunction(doc.decrypt)) {
                doc.decrypt();
            }

            return doc;
        });
    }
};