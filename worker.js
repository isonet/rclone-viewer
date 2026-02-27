importScripts('https://cdnjs.cloudflare.com/ajax/libs/tweetnacl/1.0.3/nacl.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/scrypt-js/3.0.1/scrypt.js');

self.onmessage = async function (e) {
    if (e.data.type === 'deriveKeys') {
        const { password, salt } = e.data;
        const passBytes = new TextEncoder().encode(password);
        const defaultSalt = new Uint8Array([0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1]);
        const saltBytes = salt ? new TextEncoder().encode(salt) : defaultSalt;

        try {
            const keyBytes = await scrypt.scrypt(passBytes, saltBytes, 16384, 8, 1, 80);
            self.postMessage({
                type: 'keysDerived', keys: {
                    dataKey: keyBytes.slice(0, 32),
                    nameKey: keyBytes.slice(32, 64),
                    nameTweak: keyBytes.slice(64, 80)
                }
            });
        } catch (err) {
            self.postMessage({ type: 'error', error: 'Key derivation failed' });
        }
    } else if (e.data.type === 'decrypt') {
        const { file, dataKey } = e.data;
        try {
            const headerBuffer = await file.slice(0, 32).arrayBuffer();
            if (headerBuffer.byteLength < 32) throw new Error("File too small");

            const magicStr = new TextDecoder().decode(new Uint8Array(headerBuffer, 0, 8));
            if (magicStr !== "RCLONE\0\0") throw new Error("Not a valid rclone crypt file");

            const baseNonce = new Uint8Array(headerBuffer, 8, 24);
            const CHUNK_SIZE = 64 * 1024 + 16;
            const totalChunks = Math.ceil((file.size - 32) / CHUNK_SIZE);
            const decryptedBlobs = [];

            for (let i = 0; i < totalChunks; i++) {
                const offset = 32 + i * CHUNK_SIZE;
                const chunkBlob = file.slice(offset, offset + CHUNK_SIZE);
                const chunkBytes = new Uint8Array(await chunkBlob.arrayBuffer());

                const blockNonce = new Uint8Array(24);
                blockNonce.set(baseNonce);
                const view = new DataView(blockNonce.buffer);
                const low = view.getUint32(0, true);
                const high = view.getUint32(4, true);
                let newLow = low + i;
                let newHigh = high + Math.floor(newLow / 0x100000000);
                view.setUint32(0, newLow >>> 0, true);
                view.setUint32(4, newHigh >>> 0, true);

                const decryptedChunk = nacl.secretbox.open(chunkBytes, blockNonce, dataKey);
                if (!decryptedChunk) throw new Error("Incorrect password or corrupted block");
                decryptedBlobs.push(new Blob([decryptedChunk]));

                if (i % 5 === 0 || i === totalChunks - 1) {
                    self.postMessage({ type: 'progress', progress: Math.min(100, Math.round(((i + 1) / totalChunks) * 100)) });
                }
            }
            self.postMessage({ type: 'done', result: new Blob(decryptedBlobs) });
        } catch (err) {
            self.postMessage({ type: 'error', error: err.message });
        }
    }
};
