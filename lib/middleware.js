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
     * Register pre middleware
     */
    schema.pre('init', function (doc) {
        this.encAuthenticate.call(this, doc);
        this.encDecrypt.call(this, doc);
    });

    schema.pre('save', async function () {
        // TODO Ensure all encrypt fields are present
        await this.encEncrypt();
    });

    schema.pre('update', async function () {
        preUpdate.call(this);
        preFind.call(this);
    });

    schema.pre('insertMany', async function (next, docs) {
        // TODO Encrypt docs
        /*
        const fieldsToEncrypt = this.schema.encryption.fieldsToEncrypt;

        if (_.isArray(docs)) {

        }
        else {
            console.log('enc', docs.encrypt);
        }
        console.log('docs', docs);
        console.log('this.schema', this.schema.encryption);
        */
    });

    schema.pre('find', preFind);
    schema.pre('findOne', preFind);
    schema.pre('findOneAndRemove', preFind);
    schema.pre('findOneAndUpdate', function () {
        preFind.call(this);
        preUpdate.call(this);
    });
    schema.pre('count', preFind);

    /**
     * Register post middleware
     */
    if (pluginOptions.decryptAfterSave) {
        schema.post('save', function (doc) {
            if (_.isFunction(doc.encDecrypt)) {
                doc.encDecrypt();
            }

            return doc;
        });
    }

    /**
     * Functions
     */
    function preFind () {
        const fieldsWithHash = this.schema.encryption.fieldsWithHash;
        const query = this.getQuery();

        function processQuery (query, path) {
            // Actual query alterations happen here
            if (_.has(query, path)) {
                query[`${config.HASH_FIELD_NAME}.${path}`] = crypto.computeHMAC(_.get(query, path), pluginOptions.hashingKey, 'base64');
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
};