const crypto = require('crypto');

function generateSecret() {
  const secret = crypto.randomBytes(10).toString('base64');
  return secret;
}

function generateTOTP(secret, time = null, digits = 6, step = 30) {
  const timeInSeconds = Math.floor((time || Date.now()) / 1000);
  const counter = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    counter[i] = timeInSeconds & 0xff;
    timeInSeconds = Math.floor(timeInSeconds / 256);
  }

  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base64'));
  hmac.update(counter);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

function verifyTOTP(secret, token, window = 0, digits = 6) {
  const currentTime = Math.floor(Date.now() / 1000);

  for (let i = -window; i <= window; i++) {
    const totp = generateTOTP(secret, currentTime + i);
    if (token === totp) {
      return true;
    }
  }

  return false;
}

function generateHOTP(secret, counter, digits = 6) {
  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base64'));
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUIntBE(counter, 0, 8);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

function verifyHOTP(secret, token, counter, digits = 6) {
  const totp = generateHOTP(secret, counter, digits);
  return token === totp;
}

module.exports = {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  generateHOTP,
  verifyHOTP,
};
