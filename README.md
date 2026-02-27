# Rclone Crypt Viewer

A purely client-side, offline-capable web application that decrypts and previews Rclone crypt files directly in your browser.

## Features

- **100% Client-Side**: No files are ever uploaded or sent to a server. All decryption happens locally in your browser using WebCrypto and Web Workers.
- **Offline Capable**: All dependencies (Tailwind-like custom CSS, cryptography libraries) are stored locally in the `libs/` directory. You do not need an internet connection to use the viewer.
- **Format Support**: Automatically detects and decrypts Base32, Base36, and Base64 encoded file names (using Rclone's EME algorithm with PKCS#7 padding validation).
- **Rich Previews**: Instant in-browser previews for:
  - Images (`jpg`, `png`, `gif`, `webp`, `svg`)
  - Videos (`mp4`, `webm`, `mov`)
  - Audio (`mp3`, `wav`, `flac`)
  - Text Files (`txt`, `md`, `json`, `csv`, `js`, `html`, `css`, `log`)
- **Web Worker Acceleration**: Offloads Scrypt key derivation and NaCl Secretbox block decryption to a dedicated web worker to keep the UI perfectly smooth.

## Usage

1. Open `index.html` in any modern web browser.
2. Enter your Rclone **Password** and **Salt** (optional, defaults to Rclone's standard salt if left blank).
   > *Tip: You can use the "UNOBSCURE" button to easily copy-paste obscured passwords directly from your `rclone.conf` file.*
3. Drag and drop encrypted files or folders into the application.
4. The file list will automatically decrypt the file names.
5. Click on any file to decrypt its contents and preview it or save the resulting decrypted file.

## Technical Details

This project uses exact logical translations of Rclone's Golang cryptographic routines into JavaScript:

- **Key Derivation**: `scrypt` (16384, 8, 1, 80) is used to generate the 32-byte Data Key, 32-byte Name Key, and 16-byte Name Tweak.
- **File Decryption**: NaCl `secretbox` is used to decrypt the 64k data blocks, tracking the nonces according to Rclone's block offset specification.
- **Filename Decryption**: Custom AES-EME (Encrypt-Mix-Encrypt) wide-block deciphering to strictly match Rclone's filename encryption module.

## External Libraries

The `libs/` folder contains exactly three external dependencies required for the cryptography math to function:

- **tweetnacl.js**: Curve25519/Salsa20/Poly1305 bindings for decrypting the file bodies.
- **scrypt-js**: For generating the AES keys from the password & salt.
- **aes-js**: Pure JS implementation of AES for the EME block cipher.

## License

MIT License
