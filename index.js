const crypto = require('crypto');
let bytes = 10;
let encoding = 'base64';
let algorithm = 'sha1';
let digits = 6
let step = 30

function generateSecret() {
  const secret = crypto.randomBytes(bytes).toString(encoding);
  return secret;
}

function generateTOTP(secret, time = null, digits, step) {
  const currentTime = time || Date.now();
  const timeInSeconds = Math.floor(currentTime / 1000);
  const counter = Buffer.alloc(8);
  let timeCounter = Math.floor(timeInSeconds / step)
 /* Why 8 Bytes? The HOTP and TOTP algorithms specify that the counter value used in the HMAC computation should be an 8-byte (64-bit) integer. 
 This is because the counter needs to support a large range of values allowing a very high number of possible one-time passwords.*/
  
 for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = timeCounter & 0xff;
    timeCounter = Math.floor(timeCounter / 256);
  }

  const algorithm = 'sha1';
  const encoding = 'base64';
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

function verifyHOTP(secret, token, counter, digits) {
  const hotp = generateHOTP(secret, counter, digits);
  return token === hotp;
}

module.exports = {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  generateHOTP,
  verifyHOTP,
};
