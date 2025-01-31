const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ENCRYPTION_KEY = process.env.ENCRYPTION_SECRET_KEY;
const IV_LENGTH = 16; // AES requires a 16-byte IV

// 🔐 Encrypt a file before saving
function encryptFile(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY, "hex"),
      iv
    );

    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);

    output.write(iv); // Store IV at the beginning for decryption

    input.pipe(cipher).pipe(output);

    output.on("finish", () => resolve(outputPath));
    output.on("error", reject);
  });
}

// 🔓 Decrypt a file before downloading
function decryptFile(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);

    const iv = Buffer.alloc(IV_LENGTH);
    input.read(IV_LENGTH, iv); // Read IV from start of the file

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY, "hex"),
      iv
    );

    input.pipe(decipher).pipe(output);

    output.on("finish", () => resolve(outputPath));
    output.on("error", reject);
  });
}

module.exports = { encryptFile, decryptFile };
