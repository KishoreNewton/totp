import { createHmac, randomUUID } from "crypto";
import * as QRCodeTerminal from "qrcode-terminal";
import * as QRCode from "qrcode";
import * as readline from "readline";

// Convert a base32 string into a hex string.
function base32ToHex(base32: string): string {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let hex = "";

  for (let i = 0; i < base32.length; i++) {
    const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
    bits += leftPad(val.toString(2), 5, "0");
  }

  for (let i = 0; i + 4 <= bits.length; i += 4) {
    const chunk = bits.substr(i, 4);
    hex += parseInt(chunk, 2).toString(16);
  }

  return hex;
}

function leftPad(str: string, len: number, ch: string): string {
  len = len - str.length + 1;
  return Array(len).join(ch) + str;
}

function generateTOTP(
  secret: string,
  algorithm = "sha1",
  digits = 6,
  period = 30
): string {
  const timeCounter = Math.floor(Date.now() / 1000 / period);
  const hexCounter = leftPad(timeCounter.toString(16), 16, "0");

  const decodedSecret = Buffer.from(base32ToHex(secret), "hex");
  const hmac = createHmac(algorithm, decodedSecret)
    .update(Buffer.from(hexCounter, "hex"))
    .digest();

  const offset = hmac[hmac.length - 1] & 0xf;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binaryCode % Math.pow(10, digits);

  return leftPad(otp.toString(), digits, "0");
}

// Usage
const secret = "NB2W45DFOIZA";
const token = generateTOTP(secret);
console.log("Your Generated Token is:", token);

function confirm(
  userToken: string,
  secret: string,
  tolerance = 1,
  algorithm = "sha1",
  digits = 6,
  period = 30
): boolean {
  const currentToken = generateTOTP(secret, algorithm, digits, period);

  // If userToken matches the currentToken, return true
  if (userToken === currentToken) return true;

  // If a tolerance is set (for clock drift or slight time mismatches),
  // generate tokens for the previous and next intervals.
  for (let i = 1; i <= tolerance; i++) {
    if (
      userToken ===
      generateTOTPForTimeOffset(secret, i, algorithm, digits, period) ||
      userToken ===
      generateTOTPForTimeOffset(secret, -i, algorithm, digits, period)
    ) {
      return true;
    }
  }

  return false;
}

function generateTOTPForTimeOffset(
  secret: string,
  offset: number,
  algorithm = "sha1",
  digits = 6,
  period = 30
): string {
  const timeCounter = Math.floor(Date.now() / 1000 / period) + offset;
  const hexCounter = leftPad(timeCounter.toString(16), 16, "0");

  const decodedSecret = Buffer.from(base32ToHex(secret), "hex");
  const hmac = createHmac(algorithm, decodedSecret)
    .update(Buffer.from(hexCounter, "hex"))
    .digest();

  const offsetByte = hmac[hmac.length - 1] & 0xf;
  const binaryCode =
    ((hmac[offsetByte] & 0x7f) << 24) |
    ((hmac[offsetByte + 1] & 0xff) << 16) |
    ((hmac[offsetByte + 2] & 0xff) << 8) |
    (hmac[offsetByte + 3] & 0xff);

  const otp = binaryCode % Math.pow(10, digits);

  return leftPad(otp.toString(), digits, "0");
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});


function generateQRCode(secret: string): void {
  const label = encodeURIComponent("test@pionglobal.com");  // Replace with appropriate label
  const issuer = encodeURIComponent("PionGlobal");  // Replace with your app's name
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`;

  QRCode.toDataURL(uri, (err: any, url: any) => {
    if (err) {
      console.error("Failed to generate QR Code:", err);
      return;
    }

    // console.log("Scan this QR Code with your authenticator app:", url);
  });
}

generateQRCode(secret);

function generateQRCodeInTerminal(secret: string): void {
  const label = encodeURIComponent(randomUUID());  // Replace with appropriate label
  const issuer = encodeURIComponent("New Name");  // Replace with your app's name
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}`;

  QRCodeTerminal.generate(uri, { small: true }, function(qr) {
    console.log(qr);
  });
}

// Usage
generateQRCodeInTerminal(secret);


rl.question("Your Token?", (name: string) => {
  // Usage
  const userProvidedToken = name;
  const isTokenValid = confirm(userProvidedToken, secret);
  console.log(isTokenValid ? "Valid token!" : "Invalid token!");
  rl.close();
});
