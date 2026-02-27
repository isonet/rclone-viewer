// Debug Hex Helper
function toHex(u8array) {
    if (!u8array) return "null";
    return Array.from(u8array).map(b => b.toString(16).padStart(2, '0')).join('');
}

const state = {
    password: '',
    salt: '',
    encoding: 'auto',
    showPassword: false,
    keys: null,
    files: [],
    selectedFile: null,
    previewState: 'idle',
    previewData: null,
    previewError: '',
    progress: 0
};

const DOM = {
    pass: document.getElementById('input-password'),
    salt: document.getElementById('input-salt'),
    enc: document.getElementById('input-encoding'),
    btnToggleVis: document.getElementById('btn-toggle-visibility'),
    iconVis: document.getElementById('icon-visibility'),
    btnPassUnobscure: document.getElementById('btn-unobscure-pass'),
    btnSaltUnobscure: document.getElementById('btn-unobscure-salt'),
    keyStatus: document.getElementById('key-status'),
    fileList: document.getElementById('file-list'),
    previewTitle: document.getElementById('preview-title'),
    previewContainer: document.getElementById('preview-container'),
    uploadFiles: document.getElementById('upload-files'),
    uploadFolder: document.getElementById('upload-folder')
};

let activeWorker = null;
let keyDeriveTimer = null;

// ==========================================
// Cryptography Helpers
// ==========================================
function xorBlocks(a, b) {
    const res = new Uint8Array(16);
    for (let i = 0; i < 16; i++) res[i] = a[i] ^ b[i];
    return res;
}

function multBy2(inBlock) {
    const out = new Uint8Array(16);
    out[0] = (inBlock[0] << 1) & 0xff;
    if (inBlock[15] >= 128) out[0] ^= 135;
    for (let j = 1; j < 16; j++) {
        out[j] = ((inBlock[j] << 1) | (inBlock[j - 1] >> 7)) & 0xff;
    }
    return out;
}

function emeDecrypt(aes, tweak, C) {
    const m = C.length / 16;
    if (m === 0) return new Uint8Array(0);

    const LTable = new Array(m);
    let Li = aes.encrypt(new Uint8Array(16));
    for (let i = 0; i < m; i++) {
        Li = multBy2(Li);
        LTable[i] = Li;
    }

    const C_out = new Array(m);
    for (let j = 0; j < m; j++) {
        const Pj = C.slice(j * 16, (j + 1) * 16);
        const PPj = xorBlocks(Pj, LTable[j]);
        C_out[j] = aes.decrypt(PPj);
    }

    let MP = new Uint8Array(16);
    MP = xorBlocks(C_out[0], tweak);
    for (let j = 1; j < m; j++) {
        MP = xorBlocks(MP, C_out[j]);
    }

    const MC = aes.decrypt(MP);

    let M = xorBlocks(MP, MC);

    for (let j = 1; j < m; j++) {
        M = multBy2(M);
        C_out[j] = xorBlocks(C_out[j], M);
    }

    let CCC1 = xorBlocks(MC, tweak);
    for (let j = 1; j < m; j++) {
        CCC1 = xorBlocks(CCC1, C_out[j]);
    }
    C_out[0] = CCC1;

    const P_out = new Uint8Array(C.length);
    for (let j = 0; j < m; j++) {
        const CCj = aes.decrypt(C_out[j]);
        const Pj_out = xorBlocks(CCj, LTable[j]);
        P_out.set(Pj_out, j * 16);
    }

    return P_out;
}

// Extremely strict PKCS#7 Unpadder to ensure Auto-Detection is flawless
function unpadPKCS7(buf) {
    if (buf.length === 0) return buf;
    const padLen = buf[buf.length - 1];
    if (padLen === 0 || padLen > 16 || padLen > buf.length) {
        throw new Error("Invalid PKCS#7 padding length");
    }
    for (let i = buf.length - padLen; i < buf.length; i++) {
        if (buf[i] !== padLen) {
            throw new Error("Invalid PKCS#7 padding byte");
        }
    }
    return buf.slice(0, buf.length - padLen);
}

function decodeBase32(str) {
    const lower = str.toLowerCase().replace(/=+$/, '');
    const alphabet = "0123456789abcdefghijklmnopqrstuv";

    let bits = 0, value = 0;
    const output = [];
    for (let i = 0; i < lower.length; i++) {
        const char = lower[i];
        const idx = alphabet.indexOf(char);
        if (idx === -1) {
            return null;
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 255);
            bits -= 8;
            value = value & ((1 << bits) - 1);
        }
    }
    return new Uint8Array(output);
}

function decodeBase36(str) {
    if (!str) return new Uint8Array(0);
    str = str.toLowerCase();
    let num = 0n;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        let d = 0n;
        if (c >= 48 && c <= 57) d = BigInt(c - 48); // 0-9
        else if (c >= 97 && c <= 122) d = BigInt(c - 87); // a-z
        else return null;
        num = num * 36n + d;
    }

    let hex = num.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    const m = Math.ceil(bytes.length / 16);
    const blockAlignedLen = m === 0 ? 16 : m * 16;

    if (bytes.length < blockAlignedLen) {
        const padded = new Uint8Array(blockAlignedLen);
        padded.set(bytes, blockAlignedLen - bytes.length);
        return padded;
    }
    return bytes;
}

function decodeBase64(str) {
    try {
        let clean = str.replace(/-/g, '+').replace(/_/g, '/');
        while (clean.length % 4 !== 0) clean += '=';
        const binary = atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    } catch (e) {
        return null;
    }
}

function decryptFileName(encodedName, encoding, nameKey, nameTweak) {
    if (!encodedName || encoding === 'off') return encodedName;

    function tryDecryptSegment(part) {
        console.group(`Decrypting Segment: ${part}`);
        const encodingsToTry = encoding === 'auto' ? ['base36', 'base32', 'base64'] : [encoding];
        let lastError = null;

        for (const enc of encodingsToTry) {
            console.log(`Trying format: ${enc}...`);
            let encryptedBytes;

            if (enc === 'base32') encryptedBytes = decodeBase32(part);
            else if (enc === 'base36') encryptedBytes = decodeBase36(part);
            else if (enc === 'base64') encryptedBytes = decodeBase64(part);

            if (!encryptedBytes || encryptedBytes.length === 0) {
                console.log(`-> Skipped`);
                continue;
            }

            if (encryptedBytes.length % 16 !== 0) {
                console.log(`-> Skipped: Violates EME 16-byte block requirement.`);
                continue;
            }

            try {
                const aes = new window.aesjs.AES(nameKey);
                const decryptedPadded = emeDecrypt(aes, nameTweak, encryptedBytes);
                const decryptedBytes = unpadPKCS7(decryptedPadded);
                const resultStr = new TextDecoder("utf-8", { fatal: true }).decode(decryptedBytes);

                console.log(`-> SUCCESS with ${enc}! Decrypted to:`, resultStr);
                console.groupEnd();
                return resultStr;
            } catch (e) {
                console.log(`-> Failed: ${e.message}`);
                lastError = e.message;
            }
        }

        console.groupEnd();
        if (encoding !== 'auto' && lastError) {
            return `[Err: ${lastError}] ${part.substring(0, 10)}...`;
        }
        return part;
    }

    if (encodedName.includes('_')) {
        const subParts = encodedName.split('_');
        return subParts.map(tryDecryptSegment).join('_');
    }

    return tryDecryptSegment(encodedName);
}

async function unobscurePassword(obscuredStr) {
    let base64 = obscuredStr.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    const binary = atob(base64);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i);

    if (data.length < 16) throw new Error("String too short");

    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);
    const cryptKey = new Uint8Array([
        0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d,
        0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
        0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb,
        0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38
    ]);

    const key = await crypto.subtle.importKey('raw', cryptKey, { name: 'AES-CTR' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

// ==========================================
// UI & Render Logic
// ==========================================
function updateFileNames() {
    state.files.forEach(f => {
        const path = f.file.webkitRelativePath || f.file.name;
        let decName = path;
        if (state.keys && state.encoding !== 'off') {
            const parts = path.split('/');
            const decParts = parts.map(p => decryptFileName(p, state.encoding, state.keys.nameKey, state.keys.nameTweak));
            decName = decParts.join('/');
        }
        f.decryptedName = decName;
    });
    renderFiles();
}

function triggerKeyDerivation() {
    if (!state.password) {
        state.keys = null;
        updateFileNames();
        DOM.keyStatus.classList.add('hidden');
        return;
    }

    state.keys = null;
    DOM.keyStatus.classList.remove('hidden');

    clearTimeout(keyDeriveTimer);
    keyDeriveTimer = setTimeout(() => {
        const worker = new Worker('worker.js');
        worker.onmessage = (e) => {
            if (e.data.type === 'keysDerived') {
                state.keys = e.data.keys;
                updateFileNames();
            }
            DOM.keyStatus.classList.add('hidden');
            worker.terminate();
        };
        worker.postMessage({ type: 'deriveKeys', password: state.password, salt: state.salt });
    }, 500);
}

function renderFiles() {
    DOM.fileList.innerHTML = '';
    if (state.files.length === 0) {
        DOM.fileList.innerHTML = '<div class="empty-files">Upload a file to begin. Open F12 Console to see debug logs.</div>';
        return;
    }

    state.files.forEach(f => {
        const isSelected = state.selectedFile === f.id;
        const fileName = f.decryptedName.split('/').pop();
        const pathParts = f.decryptedName.split('/');
        const pathPrefix = pathParts.length > 1 ? pathParts.slice(0, -1).join('/') : '';

        const el = document.createElement('div');
        el.className = `file-item ${isSelected ? 'selected' : ''}`;
        el.onclick = () => handleSelectFile(f);

        el.innerHTML = `
            <svg viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            <div class="file-item-info">
                <div class="file-item-name truncate">${fileName}</div>
                ${pathPrefix ? `<div class="file-item-path truncate">${pathPrefix}</div>` : ''}
            </div>
        `;
        DOM.fileList.appendChild(el);
    });
}

function renderPreview() {
    DOM.previewTitle.textContent = state.previewState === 'ready' && state.previewData
        ? state.previewData.name.split('/').pop()
        : 'Preview Canvas';

    let content = '';

    if (state.previewState === 'idle') {
        content = `
            <div class="idle-state animate-pulse">
                <svg viewBox="0 0 24 24"><path d="m12 14 4-4"></path><path d="M3.3 7 8.7 1.6a2.4 2.4 0 0 1 3.4 0l5.4 5.4a2.4 2.4 0 0 1 0 3.4L12.1 15.8a2.4 2.4 0 0 1-3.4 0L3.3 10.4a2.4 2.4 0 0 1 0-3.4z"></path></svg>
                <p>Select an encrypted file to view</p>
            </div>`;
    } else if (state.previewState === 'decrypting') {
        content = `
            <div class="decrypting-state">
                <svg class="animate-bounce" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                <div class="progress-bar-wrap">
                    <div class="progress-stats">
                        <span>Decrypting...</span>
                        <span>${state.progress}%</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill" style="width: ${state.progress}%"></div>
                    </div>
                </div>
            </div>`;
    } else if (state.previewState === 'error') {
        content = `
            <div class="error-state">
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                <div class="error-title">${state.previewError}</div>
                <div class="error-desc">Please verify your password and salt match rclone.conf.</div>
            </div>`;
    } else if (state.previewState === 'ready' && state.previewData) {
        const ext = state.previewData.name.split('.').pop().toLowerCase();
        const { url, blob, name } = state.previewData;
        const downloadBtn = `
            <a href="${url}" download="${name.split('/').pop()}" class="download-btn">
                <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Save File
            </a>`;

        if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext)) {
            content = `${downloadBtn}<img src="${url}" alt="Preview" class="preview-img" />`;
        } else if (['mp4', 'webm', 'ogg', 'mov'].includes(ext)) {
            content = `${downloadBtn}<video src="${url}" controls class="preview-video"></video>`;
        } else if (['mp3', 'wav', 'flac', 'm4a'].includes(ext)) {
            content = `
                ${downloadBtn}
                <div class="preview-audio-wrap">
                    <div class="audio-icon-wrap">
                        <svg viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"></path><circle cx="6" cy="18" r="3"></circle><circle cx="18" cy="16" r="3"></circle></svg>
                    </div>
                    <div class="audio-title">${name.split('/').pop()}</div>
                    <audio src="${url}" controls></audio>
                </div>`;
        } else if (['txt', 'md', 'json', 'csv', 'js', 'html', 'css', 'log', 'xml'].includes(ext)) {
            content = `${downloadBtn}
                <div class="preview-text-wrap">
                    <pre id="text-preview-content" class="preview-text-content">Loading text...</pre>
                </div>`;

            const limit = 100 * 1024;
            blob.slice(0, limit).text().then(t => {
                const el = document.getElementById('text-preview-content');
                if (el) el.textContent = t + (blob.size > limit ? '\n\n... [File truncated for preview purposes]' : '');
            });
        } else {
            content = `
                ${downloadBtn}
                <div class="preview-generic-wrap">
                    <svg class="generic-icon" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    <div class="text-center">
                        <div class="generic-title">${name.split('/').pop()}</div>
                        <div class="generic-meta">Decrypted successfully &middot; ${(blob.size / 1024 / 1024).toFixed(2)} MB</div>
                    </div>
                </div>`;
        }
    }

    DOM.previewContainer.innerHTML = content;
}

// ==========================================
// Event Handlers
// ==========================================
DOM.pass.addEventListener('input', (e) => { state.password = e.target.value; triggerKeyDerivation(); });
DOM.salt.addEventListener('input', (e) => { state.salt = e.target.value; triggerKeyDerivation(); });
DOM.enc.addEventListener('change', (e) => { state.encoding = e.target.value; updateFileNames(); });

DOM.btnToggleVis.addEventListener('click', () => {
    state.showPassword = !state.showPassword;
    DOM.pass.type = state.showPassword ? 'text' : 'password';
    DOM.salt.type = state.showPassword ? 'text' : 'password';

    // Switch icon between eye and eye-off
    if (state.showPassword) {
        DOM.iconVis.innerHTML = '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path><line x1="2" y1="2" x2="22" y2="22"></line>';
    } else {
        DOM.iconVis.innerHTML = '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle>';
    }
});

const handleUnobscure = async (inputEl, stateKey) => {
    const val = inputEl.value;
    if (!val) return;
    try {
        const plain = await unobscurePassword(val);
        inputEl.value = plain;
        state[stateKey] = plain;
        triggerKeyDerivation();
    } catch (e) {
        alert("Could not unobscure. Are you sure this is an obscured string copied directly from rclone.conf?");
    }
};

DOM.btnPassUnobscure.addEventListener('click', () => handleUnobscure(DOM.pass, 'password'));
DOM.btnSaltUnobscure.addEventListener('click', () => handleUnobscure(DOM.salt, 'salt'));

const handleFileUpload = (e) => {
    const droppedFiles = Array.from(e.target.files);
    if (droppedFiles.length === 0) return;

    const newFiles = droppedFiles.map(f => ({
        file: f,
        decryptedName: f.webkitRelativePath || f.name,
        id: crypto.randomUUID()
    }));

    state.files.push(...newFiles);
    e.target.value = null;
    updateFileNames();
};

DOM.uploadFiles.addEventListener('change', handleFileUpload);
DOM.uploadFolder.addEventListener('change', handleFileUpload);

function handleSelectFile(fileObj) {
    state.selectedFile = fileObj.id;
    renderFiles();

    if (!state.keys || !state.keys.dataKey) {
        state.previewState = 'error';
        state.previewError = 'Encryption keys are still being generated. Please wait a moment and try again.';
        renderPreview();
        return;
    }

    state.previewState = 'decrypting';
    state.progress = 0;
    renderPreview();

    if (state.previewData && state.previewData.url) {
        URL.revokeObjectURL(state.previewData.url);
    }
    state.previewData = null;

    if (activeWorker) activeWorker.terminate();

    const worker = new Worker('worker.js');
    activeWorker = worker;

    worker.onmessage = (e) => {
        if (e.data.type === 'progress') {
            state.progress = e.data.progress;
            renderPreview();
        } else if (e.data.type === 'done') {
            const resultBlob = e.data.result;
            const url = URL.createObjectURL(resultBlob);
            state.previewData = { blob: resultBlob, url, name: fileObj.decryptedName };
            state.previewState = 'ready';
            renderPreview();
            worker.terminate();
        } else if (e.data.type === 'error') {
            state.previewState = 'error';
            state.previewError = e.data.error;
            renderPreview();
            worker.terminate();
        }
    };

    worker.postMessage({
        type: 'decrypt',
        file: fileObj.file,
        dataKey: state.keys.dataKey
    });
}

