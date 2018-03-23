# mongoose-advanced-encryption

Mongoose plugin for document fields encryption and authentication preserving ability to query for encrypted field.

## Overview

## Plugin Options

- `encryptionKey` -
- `authenticationKey` - 
- `decryptAfterSave` - (defaults to `false`) Enables automatic documents decryption passed to `doc.save()` callback.
- `encrypt` - Allows to adjust plugin's default field encryption options on per schema level. 
    These options can be overridden on per field level.  
    - `hash` - Indicates either hash should be created or not.
        - `index` (defaults to `false`) - Indicates either index for the hash field should be created of not.
    
## Instance Methods

- `encrypt`
- `decrypt`
- `sign`
- `authenticate`

## Credits




## Getting Started

`npm install mongoose-advanced-encryption --save`