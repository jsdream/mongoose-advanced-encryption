'use strict';

const crypto = require('crypto');
const stringify = require('json-stringify-deterministic');

const config = require('./config');

/**
 * Encrypt plaintext
 * @param data
 * @param encryptionKey
 * @returns {Promise<Buffer>}
 */
exports.encrypt = function (data, encryptionKey) {
    return new Promise((resolve, reject) => {
        // generate random iv
        crypto.randomBytes(config.IV_LENGTH, (err, iv) => {
            if (err) {
                return reject(err);
            }

            const cipher = crypto.createCipheriv(config.ENCRYPTION_ALGORITHM, encryptionKey, iv);
            const jsonToEncrypt = stringify(data, {cycles: true});

            cipher.end(jsonToEncrypt, 'utf-8', () => {
                resolve(Buffer.concat([config.VERSION_BUFFER, iv, cipher.read()]));
            });
        });
    });
};

/**
 * Decrypt cipher into plaintext
 * @param cipherText
 * @param encryptionKey
 * @returns {Object}
 */
exports.decrypt = function (cipherText, encryptionKey) {
    if (!(cipherText instanceof Buffer)) {
        throw new Error('Cipher text must be a Buffer');
    }

    const iv = cipherText.slice(config.VERSION_LENGTH, config.VERSION_LENGTH + config.IV_LENGTH);
    const ct = cipherText.slice(config.VERSION_LENGTH + config.IV_LENGTH, cipherText.length);

    const decipher = crypto.createDecipheriv(config.ENCRYPTION_ALGORITHM, encryptionKey, iv);

    let decrypted;

    try {
        const decryptedJSON = decipher.update(ct, undefined, 'utf8') + decipher.final('utf8');
        decrypted = JSON.parse(decryptedJSON);
    } catch (err) {
        throw new Error('Error parsing JSON during decrypt of ' + path + ' field: ' + err);
    }

    return decrypted;
};

/**
 * Compute HMAC
 * @param data
 * @param {string} key
 * @param {string} [encoding]
 * @returns {Buffer|string}
 */
exports.computeHMAC = function (data, key, encoding) {
    return crypto.createHmac('sha512', key)
        .update(stringify(data))
        .digest(encoding);
};