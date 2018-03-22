'use strict';

const crypto = require('crypto');

const IV_LENGTH = 16;
const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const VERSION = '1';
const VERSION_LENGTH = 1;
const VERSION_BUFFER = new Buffer(VERSION);

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

exports.decrypt = function (path, encryptionKey) {
    // TODO Decrypt
};