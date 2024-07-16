
# TOTP and HOTP Implementation

This package provides functionality to generate and verify Time-based One-Time Passwords (TOTP) and HMAC-based One-Time Passwords (HOTP) using the `crypto` module in Node.js. The implementation follows the RFC 4226 (HOTP) and RFC 6238 (TOTP) standards.

## Installation

To use this package, you need to have Node.js installed. You can include this code in your project by copying the provided functions into a file, or by creating a module.

## Usage

### Configuration

You can configure the number of bytes, encoding, algorithm, number of digits, and step as needed:

``` javascript
const crypto = require('crypto');
let bytes = 10;
let encoding = 'base64';
let algorithm = 'sha1';
let digits = 6;
let step = 30;
```

### Functions

#### `generateSecret()`

Generates a secret key for TOTP/HOTP.

``` javascript
function generateSecret() {
  const secret = crypto.randomBytes(bytes).toString(encoding);
  return secret;
}
```

#### `generateTOTP(secret, time = null, digits, step)`

Generates a TOTP based on the provided secret, time, number of digits, and step.

``` javascript
function generateTOTP(secret, time = null, digits, step) {
  const currentTime = time || Date.now();
  const timeInSeconds = Math.floor(currentTime / 1000);
  const counter = Buffer.alloc(8);
  let timeCounter = Math.floor(timeInSeconds / step);

  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = timeCounter & 0xff;
    timeCounter = Math.floor(timeCounter / 256);
  }

  const hmac = crypto.createHmac(algorithm, Buffer.from(secret, encoding));
  hmac.update(counter);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const mod = Math.pow(10, digits);
  const otp = binary % mod;
  return otp.toString().padStart(digits, '0');
}
```

#### `verifyTOTP(secret, token, window = 0, digits, step)`

Verifies a TOTP based on the provided secret, token, window, number of digits, and step.

``` javascript
function verifyTOTP(secret, token, window = 0, digits, step) {
  const currentTime = Math.floor(Date.now() / 1000);
  for (let i = -window; i <= window; i++) {
    const adjustedTime = currentTime + i * step;
    const totp = generateTOTP(secret, adjustedTime * 1000, digits, step);
    if (token === totp) {
      return true;
    }
  }
  return false;
}
```

#### `generateHOTP(secret, counter, digits)`

Generates an HOTP based on the provided secret, counter, and number of digits.

``` javascript
function generateHOTP(secret, counter, digits) {
  const hmac = crypto.createHmac(algorithm, Buffer.from(secret, encoding));
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUIntBE(counter, 0, 8);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const mod = Math.pow(10, digits);
  const otp = binary % mod;
  return otp.toString().padStart(digits, '0');
}
```

#### `verifyHOTP(secret, token, counter, digits)`

Verifies an HOTP based on the provided secret, token, counter, and number of digits.

``` javascript
function verifyHOTP(secret, token, counter, digits) {
  const hotp = generateHOTP(secret, counter, digits);
  return token === hotp;
}
```

### Example Usage

``` javascript
const {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  generateHOTP,
  verifyHOTP,
} = require('./path/to/this/module');

const secret = generateSecret();
console.log('Secret:', secret);

const totp = generateTOTP(secret, null, digits, step);
console.log('TOTP:', totp);

const isValidTOTP = verifyTOTP(secret, totp, 1, digits, step);
console.log('Is valid TOTP:', isValidTOTP);

const hotp = generateHOTP(secret, 1, digits);
console.log('HOTP:', hotp);

const isValidHOTP = verifyHOTP(secret, hotp, 1, digits);
console.log('Is valid HOTP:', isValidHOTP);
```

### Explanation

1. **Why 8 Bytes for the Counter?**
   - The HOTP and TOTP algorithms specify that the counter value used in the HMAC computation should be an 8-byte (64-bit) integer. This allows a very high number of possible one-time passwords and ensures that the counter can support a large range of values.

2. **Why `Math.pow(10, digits)`?**
   - The base `10` is used because we are generating numeric OTPs. Raising `10` to the power of `digits` (e.g., 6) gives the range within which the OTP should fall (e.g., 0 to 999999 for a 6-digit OTP).

## License

This module is available under the [MIT License](LICENSE).
