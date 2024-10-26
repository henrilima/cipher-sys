# Cipher System
Cipher System is a utility package built with Node.js and TypeScript, providing cryptographic functions, password management, and date/time manipulation utilities. 

## Features
- **Encryption & Decryption**: Securely encrypt and decrypt text using AES-256-CBC.
- **Password Generation**: Generate secure random passwords with customizable length and character sets.
- **Password Strength Validation**: Check if a password meets defined strength criteria.
- **UUID Generation**: Generate unique identifiers (UUIDs).
- **Date Formatting**: Format dates according to specified locales and options.
- **Time Conversion**: Convert time between hours, minutes, seconds, and milliseconds.

## Installation

You can install the package via npm or yarn:
```bash
npm install cipher-sys
yarn add cipher-sys
```

## Usage

Here's a brief overview of how to use the Cipher System.

## Encryption and Decryption
```typescript
import { Cipher } from 'cipher-sys';

const cipher = new Cipher();
const password = 'myPassword@';
const passKey = 'systemKey';

// Encrypting a password
const encrypted = cipher.encrypt(password, passKey); // String
console.log('Encrypted:', encrypted);

// Decrypting the password
const decrypted = cipher.decrypt(encrypted, passKey); // String
console.log('Decrypted:', decrypted);
```

## Password Generation
```typescript
const generatedPassword = cipher.generateSecurePassword(16); // String
console.log('Generated Password:', generatedPassword);
```

## Password Strength Validation
```typescript
const isStrong = cipher.isStrongPassword('P@ssw0rd123!', {
    minLength: 12,
    minUpperCase: 2,
    minNumbers: 2,
    minSpecialChar: 1
}); // Boolean

console.log('Is strong password:', isStrong);
```

### Options:
| Option                          | Type     | Default | Description                                                        |
| ------------------------------- | -------- | ------- | ------------------------------------------------------------------ |
| `minLength`                     | `number` | `8`     | Minimum length of the password.                                    |
| `maxLength`                     | `number` | `20`    | Maximum length of the password.                                    |
| `minUpperCase`                  | `number` | `1`     | Minimum number of uppercase letters required.                      |
| `minLowerCase`                  | `number` | `1`     | Minimum number of lowercase letters required.                      |
| `minNumbers`                    | `number` | `1`     | Minimum number of numeric characters required.                     |
| `minSpecialChar`                | `number` | `1`     | Minimum number of special characters required.                     |
| `minNonAlphaNumeric`            | `number` | `1`     | Minimum number of non-alphanumeric characters required.            |
| `minUniqueChars`                | `number` | `0`     | Minimum number of unique characters required.                      |
| `minRepeatChars`                | `number` | `0`     | Minimum number of repeated characters allowed.                     |
| `minConsecutiveChars`           | `number` | `0`     | Minimum number of consecutive characters allowed.                  |
| `minConsecutiveNumeric`         | `number` | `0`     | Minimum number of consecutive numeric characters allowed.          |
| `minConsecutiveSpecialChar`     | `number` | `0`     | Minimum number of consecutive special characters allowed.          |
| `minConsecutiveNonAlphaNumeric` | `number` | `0`     | Minimum number of consecutive non-alphanumeric characters allowed. |
| `minConsecutiveUniqueChars`     | `number` | `0`     | Minimum number of consecutive unique characters allowed.           |


## UUID Generation
```typescript
const uuid = cipher.generateUUID(); // String
console.log('Generated UUID:', uuid);
```

## Date Formatting
```typescript
const formattedDate = cipher.formatDateWithLocale(new Date(), 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
}); // String

console.log('Formatted Date:', formattedDate);
```

### Options:
  
| Option         | Type                                                      | Description                                                            |
| -------------- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| `year`         | `'numeric'`, `'2-digit'`                                  | Specifies the year format (full or 2-digit).                           |
| `month`        | `'numeric'`, `'2-digit'`, `'long'`, `'short'`, `'narrow'` | Specifies the month format (number, long name, short name, or narrow). |
| `day`          | `'numeric'`, `'2-digit'`                                  | Specifies the day format (full or 2-digit).                            |
| `hour`         | `'numeric'`, `'2-digit'`                                  | Specifies the hour format (12 or 24-hour format).                      |
| `minute`       | `'numeric'`, `'2-digit'`                                  | Specifies the minute format (full or 2-digit).                         |
| `second`       | `'numeric'`, `'2-digit'`                                  | Specifies the second format (full or 2-digit).                         |
| `timeZoneName` | `'short'`, `'long'`                                       | Specifies the time zone name format (short or long).                   |


## Time Conversion
```typescript
const milliseconds = cipher.convertToMilliseconds(1, 30, 45); // String
console.log('Milliseconds:', milliseconds);

const time = cipher.convertFromMilliseconds(milliseconds); // Object { hours, minutes, seconds }
console.log('Converted Time:', time);
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss changes.