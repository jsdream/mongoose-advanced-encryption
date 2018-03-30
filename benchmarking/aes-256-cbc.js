'use strict';

const crypto = require('../lib/crypto');

const testedObject = {
    firstName: 'John',
    lastName: 'Doe',
    email: 'johndoesaved@gmail.com',
    secretData: {
        creditCardNumber: '12334566789',
        details: {
            address: 'My address'
        }
    },
    secretDataObject: {
        ssn: '2254879844',
        creditCardNumber: '6545646545645'
    },
    firstName2: 'John',
    lastName2: 'Doe',
    email2: 'johndoesaved@gmail.com',
    secretData2: {
        creditCardNumber: '12334566789',
        details: {
            address: 'My address'
        }
    },
    secretDataObject2: {
        ssn: '2254879844',
        creditCardNumber: '6545646545645'
    }
};

const ITERATIONS = 50000;
const KEY = new Buffer('GKhd2bEkC9rFpzkouE0Q1Ut4N12W94Wnwm1x7jKx4QQ=', 'base64');

async function separate () {
    const encrypted = [];

    console.time('encrypt separate');
    for (let i = 0; i < ITERATIONS; i++) {
        const encryptedObject = {};
        for (let key in testedObject) {
            encryptedObject[key] = await crypto.encrypt(testedObject[key], KEY);
        }
        encrypted.push(encryptedObject);
    }
    console.timeEnd('encrypt separate');

    console.time('decrypt separate');
    for (let i = 0; i < ITERATIONS; i++) {
        for (let key in testedObject) {
            await crypto.decrypt(encrypted[i][key], KEY);
        }
    }
    console.timeEnd('decrypt separate');
}

async function aggregated () {
    const encrypted = [];
    console.time('encrypt aggregated');
    for (let i = 0; i < ITERATIONS; i++) {
        const cipher = await crypto.encrypt(testedObject, KEY);
        encrypted.push(cipher);
    }
    console.timeEnd('encrypt aggregated');

    console.time('decrypt aggregated');
    for (let i = 0; i < ITERATIONS; i++) {
        await crypto.decrypt(encrypted[i], KEY);
    }
    console.timeEnd('decrypt aggregated');
}

async function benchmark () {
    await separate();
    await aggregated();
}

benchmark();