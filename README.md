# ahex-OTP-generator
This Node.js package provides implementations of TOTP (Time-Based One-Time Password) and HOTP (HMAC-Based One-Time Password) for secure two-factor authentication.


## Introduction

This package includes functions to generate TOTP and HOTP codes, which are commonly used in two-factor authentication (2FA) systems for enhanced security.

## Installation

Install the package using npm:

```bash
npm install ahex-otp-generator


## Usage
### Generating TOTP
```javascript
    const { generateTOTP } = require('two-factor-auth');

    const secret = 'your-secret-key';
    const token = generateTOTP(secret);
    console.log('TOTP:', token);
```
### Generating HOTP
```javascript
    const { generateHOTP } = require('two-factor-auth');

    const secret = 'your-secret-key';
    const counter = 0; // Replace with your counter value
    const token = generateHOTP(secret, counter);
    console.log('HOTP:', token);
```

### What are TOTP and HOTP?
TOTP (Time-Based One-Time Password): TOTP generates a one-time password based on the current time and a shared secret key, typically used for time-limited authentication.

HOTP (HMAC-Based One-Time Password): HOTP generates a one-time password based on a counter and a shared secret key, commonly used when the sequence of authentication events is important.

## License
This package is licensed under the MIT License. See the LICENSE file for more details.