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
 * @param path
 * @param encryptionKey
 * @returns {Promise}
 */
exports.encrypt = function (data, path, encryptionKey) {
    return new Promise((resolve, reject) => {
        // generate random iv
        crypto.randomBytes(IV_LENGTH, (err, iv) => {
            if (err) {
                return reject(err);
            }

            const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
            const jsonToEncrypt = JSON.stringify(data);

            cipher.end(jsonToEncrypt, 'utf-8', () => {
                resolve({
                    cipher: Buffer.concat([VERSION_BUFFER, iv, cipher.read()]),
                    path: path
                });
            });
        });
    });
};

/**
 * Decrypt cipher into plaintext
 * @param cipherText
 * @param path
 * @param encryptionKey
 * @returns {Promise.<{path: *, value: *}>}
 */
exports.decrypt = async function (cipherText, path, encryptionKey) {
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

    return {
        path: path,
        value: decrypted
    };
};