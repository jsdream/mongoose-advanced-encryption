'use strict';

const crypto = require('crypto');

const IV_LENGTH = 16;
const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const VERSION = '1';
const VERSION_LENGTH = 1;
const VERSION_BUFFER = new Buffer(VERSION);

/**
 * Encrypt plaintext
 * @param data
 * @param encryptionKey
 * @returns {Promise<Buffer>}
 */
exports.encrypt = function (data, encryptionKey) {
    return new Promise((resolve, reject) => {
        // generate random iv
        crypto.randomBytes(IV_LENGTH, (err, iv) => {
            if (err) {
                return reject(err);
            }

            const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
            const jsonToEncrypt = JSON.stringify(data);

            cipher.end(jsonToEncrypt, 'utf-8', () => {
                resolve(Buffer.concat([VERSION_BUFFER, iv, cipher.read()]));
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

    const iv = cipherText.slice(VERSION_LENGTH, VERSION_LENGTH + IV_LENGTH);
    const ct = cipherText.slice(VERSION_LENGTH + IV_LENGTH, cipherText.length);

    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);

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
 * Hash plaintext
 * @param data
 * @param hashingKey
 * @returns {string}
 */
exports.hash = function (data, hashingKey) {
    return crypto.createHmac('sha512', hashingKey)
        .update(data)
        .digest('base64');
};

// TODO Implement this
exports.sign = function (cipher, meta, authenticationKey) {
    return crypto.createHmac('sha512', authenticationKey)
        .update(data)
        .digest('base64');
};