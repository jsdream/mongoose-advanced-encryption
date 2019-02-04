# mongoose-advanced-encryption

Mongoose plugin for document fields encryption and authentication preserving ability to query for encrypted field.

## Overview

This plugin provides encryption, hashing (blind indexing) and authentication for Mongoose document fields.
Fields encryption is performed using `AES-256-CBC` algorithm, hashing as well as authentication using `HMAC-SHA-512`.

## Requirements



## Defining field encryption settings
The plugin works on per-field encryption basis. To mark field to be encrypted it is necessary to specify it's encryption
options using `encrypt` option on it's SchemaType definition. The `encrypt` option can be either a `boolean` 
(e.g. `true` will enable encryption of the field, `false` is the same as not setting the option at all) or an `Object`
with field's encryption settings, which would override defaults. It is possible to specify default `encrypt` options
on schema level as `encrypt` field on plugin options. 
If it's not specified plugin's [hard-coded config](#default-plugin-configuration-is-the-following) will be used.

## Getting Started

`npm install mongoose-advanced-encryption --save`

###### Generate encryption keys:
`openssl rand -base64 32; openssl rand -base64 64; openssl rand -base64 64;`


## Plugin Options

- `encryptionKey` - a 32-byte base64 string.
- `hashingKey` - a 64-byte base64 string.
- `authenticationKey` - a 64-byte base64 string.
- `decryptAfterSave` - Enables automatic documents decryption passed to `doc.save()` callback.
- `skipAuthenticationIfNoSignature` - Disables document authentication if document has no signature.
- `encrypt` - Allows to adjust plugin's default field encryption options on per schema level. 
    These options can be overridden on per field level.  
    - `hash` - Indicates either hash should be created or not.
        - `index` - Indicates either index for the hash field should be created of not.

###### Default plugin configuration is the following:
```js
const defaultConfig = {
    decryptAfterSave: false,
    encrypt: {
        hash: { // means that hash will be created, but without MongoDB index
            index: false
        }
    }
}
```

## Instance Methods

- `encEncrypt`
- `encDecrypt`
- `encSign`
- `encAuthenticate`

## Supported query methods
With the methods below encryption/decryption works transparently.
- count
- countDocuments
- find
- findOne
- findOneAndRemove
- findOneAndUpdate
- update

## Security Issue Reporting / Disclaimer

I am in no way a security expert. The plugin is a result of deep research on security-related topics,
but I do not have any underlying expertise in security. If you wish to use this plugin in your project please 
analyse the code carefully and use it at your own risk.
**If you find any security-related issues, please email me at vladyslavmashkin@gmail.com**. 
For non-security-related issues, feel free to open a Github issue or pull request.   

## Credits

Big thanks to [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) plugin authors for the source of inspiration.
The `mongoose-encryption` plugin is great, but since authors decided to keep it simple for security reasons it is not sufficient enough
for our use case. That is why a decision to write a more "advanced" plugin was made.

Also another big thanks goes to this [article](https://www.sitepoint.com/how-to-search-on-securely-encrypted-database-fields/) author.

## License

The MIT License (MIT)

Copyright (c) 2018 Vladyslav Mashkin

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
