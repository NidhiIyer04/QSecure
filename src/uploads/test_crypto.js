// src/test_crypto.js

const crypto = require('crypto');

function aesExample() {
    const key = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
    let encrypted = cipher.update('Hello World', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function rsaExample() {
    const { generateKeyPairSync } = require('crypto');
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    return publicKey.export({ type: 'pkcs1', format: 'pem' });
}

console.log(aesExample());
console.log(rsaExample());
