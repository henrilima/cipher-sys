"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cipher = void 0;
const node_crypto_1 = require("node:crypto");
class Cipher {
    // Derives a key from the given password and salt using PBKDF2
    deriveKey(password, salt) {
        return (0, node_crypto_1.pbkdf2Sync)(password, salt, Cipher.ITERATIONS, Cipher.KEY_LENGTH, "sha256");
    }
    // Encrypts the given password using a derived key
    encrypt(password, pass_key) {
        if (!password || !pass_key) {
            throw new Error("Password and user password are required");
        }
        const salt = (0, node_crypto_1.randomBytes)(Cipher.SALT_LENGTH);
        const key = this.deriveKey(pass_key, salt);
        const iv = (0, node_crypto_1.randomBytes)(Cipher.IV_LENGTH);
        const cipher = (0, node_crypto_1.createCipheriv)("aes-256-cbc", key, iv);
        let encrypted = cipher.update(password, "utf8", "hex");
        encrypted += cipher.final("hex");
        // Returns salt, IV, and encrypted text as a colon-separated string
        return `${salt.toString("hex")}:${iv.toString("hex")}:${encrypted}`;
    }
    // Decrypts the encrypted password or text using the derived key
    decrypt(encryptedPassword, pass_key) {
        if (!encryptedPassword || !pass_key) {
            throw new Error("Encrypted text and user password are required");
        }
        try {
            const parts = encryptedPassword.split(":");
            const salt = Buffer.from(parts.shift(), "hex");
            const iv = Buffer.from(parts.shift(), "hex");
            const encrypted = Buffer.from(parts.join(":"), "hex");
            const key = this.deriveKey(pass_key, salt);
            const decipher = (0, node_crypto_1.createDecipheriv)("aes-256-cbc", key, iv);
            let decrypted = decipher.update(encrypted, undefined, "utf8");
            decrypted += decipher.final("utf8");
            return decrypted;
        }
        catch (err) {
            throw new Error("Failed to decrypt the text");
        }
    }
    // Generates a secure random password of specified length
    generateSecurePassword(length = 16) {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        let password = "";
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }
        return password;
    }
    // Checks if the password meets strength criteria
    isStrongPassword(password, config = {}) {
        const { minLength = 8, maxLength = 20, minUpperCase = 1, minLowerCase = 1, minNumbers = 1, minSpecialChar = 1, minNonAlphaNumeric = 1, minUniqueChars = 0, minRepeatChars = 0, minConsecutiveChars = 0, minConsecutiveNumeric = 0, minConsecutiveSpecialChar = 0, minConsecutiveNonAlphaNumeric = 0, minConsecutiveUniqueChars = 0, } = config;
        // Check length constraints
        if (password.length < minLength || password.length > maxLength) {
            return false;
        }
        // Count character types
        const upperCaseCount = (password.match(/[A-Z]/g) || []).length;
        const lowerCaseCount = (password.match(/[a-z]/g) || []).length;
        const numberCount = (password.match(/\d/g) || []).length;
        const specialCharCount = (password.match(/[!@#$%^&*()_+]/g) || [])
            .length;
        const nonAlphaNumericCount = (password.match(/[^a-zA-Z0-9]/g) || [])
            .length;
        const uniqueChars = new Set(password).size;
        // Check minimum character requirements
        if (upperCaseCount < minUpperCase)
            return false;
        if (lowerCaseCount < minLowerCase)
            return false;
        if (numberCount < minNumbers)
            return false;
        if (specialCharCount < minSpecialChar)
            return false;
        if (nonAlphaNumericCount < minNonAlphaNumeric)
            return false;
        if (uniqueChars < minUniqueChars)
            return false;
        // Check repeating characters
        const repeatCharCounts = {};
        for (const char of password) {
            repeatCharCounts[char] = (repeatCharCounts[char] || 0) + 1;
        }
        const repeatCount = Object.values(repeatCharCounts).filter((count) => count > 1).length;
        if (repeatCount < minRepeatChars)
            return false;
        // Check consecutive characters
        const isConsecutive = (arr) => {
            let count = 1;
            for (let i = 1; i < arr.length; i++) {
                if (arr[i] === arr[i - 1]) {
                    count++;
                    if (count > minConsecutiveChars)
                        return true;
                }
                else {
                    count = 1;
                }
            }
            return false;
        };
        if (minConsecutiveChars > 0 && isConsecutive(password.split("")))
            return false;
        // Check consecutive numbers, special chars, etc.
        const numChars = password.match(/\d/g) || [];
        const specialChars = password.match(/[!@#$%^&*()_+]/g) || [];
        const nonAlphaNumericChars = password.match(/[^a-zA-Z0-9]/g) || [];
        const uniqueCharArray = [...new Set(password)];
        if (minConsecutiveNumeric > 0 && isConsecutive(numChars))
            return false;
        if (minConsecutiveSpecialChar > 0 && isConsecutive(specialChars))
            return false;
        if (minConsecutiveNonAlphaNumeric > 0 &&
            isConsecutive(nonAlphaNumericChars))
            return false;
        if (minConsecutiveUniqueChars > 0 && isConsecutive(uniqueCharArray))
            return false;
        return true;
    }
    // Compares a plain password with its encrypted counterpart
    comparePasswords(plainPassword, encryptedPassword, pass_key) {
        if (!plainPassword || !encryptedPassword || !pass_key) {
            throw new Error("Passwords and pass key are required");
        }
        const decryptedPassword = this.decrypt(encryptedPassword, pass_key);
        return plainPassword === decryptedPassword;
    }
    // Generates a UUID (Universally Unique Identifier)
    generateUUID() {
        return [1e7]
            .toString()
            .replace(/[018]/g, (c) => (c ^
            crypto.getRandomValues(new Uint8Array(1))[0] % 16).toString(16));
    }
    // Formats a date to a specific locale
    formatDateWithLocale(date, locale = "en-US", options) {
        const defaultOptions = {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
        };
        const formatOptions = Object.assign(Object.assign({}, defaultOptions), options);
        return date.toLocaleDateString(locale, formatOptions);
    }
    // Converts hours, minutes, and seconds to milliseconds
    convertToMilliseconds(hours, minutes, seconds) {
        if (typeof hours !== "number" ||
            typeof minutes !== "number" ||
            typeof seconds !== "number" ||
            hours < 0 ||
            minutes < 0 ||
            seconds < 0) {
            throw new Error("Invalid input: all parameters must be non-negative numbers");
        }
        return (hours * 3600 + minutes * 60 + seconds) * 1000;
    }
    // Converts milliseconds to hours, minutes, and seconds
    convertFromMilliseconds(milliseconds) {
        if (typeof milliseconds !== "number" || milliseconds < 0) {
            throw new Error("Invalid input: milliseconds must be a non-negative number.");
        }
        const totalSeconds = Math.floor(milliseconds / 1000);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        return { hours, minutes, seconds };
    }
}
exports.Cipher = Cipher;
Cipher.ITERATIONS = 100000;
Cipher.KEY_LENGTH = 32;
Cipher.SALT_LENGTH = 16;
Cipher.IV_LENGTH = 16;
