const DATABASE_NAME = 'evidence-locker-private';
const DATABASE_VERSION = 1;
const KEY_ID = 'evidence-encryption-key';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function openVault() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      const records = database.createObjectStore('records', { keyPath: 'id' });
      records.createIndex('caseId', 'caseId', { unique: false });
      database.createObjectStore('keys', { keyPath: 'id' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open private browser storage.'));
  });
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Browser storage request failed.'));
  });
}

function putRecord(database, storeName, value) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const request = transaction.objectStore(storeName).put(value);
    let result;
    request.onsuccess = () => { result = request.result; };
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => reject(transaction.error || new Error('Browser storage write failed.'));
    transaction.onabort = () => reject(transaction.error || new Error('Browser storage write was interrupted.'));
  });
}

async function getEncryptionKey(database) {
  const stored = await requestResult(database.transaction('keys', 'readonly').objectStore('keys').get(KEY_ID));
  if (stored?.key) return stored.key;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await putRecord(database, 'keys', { id: KEY_ID, key });
  return key;
}

async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: Array.from(iv), ciphertext };
}

async function decryptBytes(key, encrypted) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) }, key, encrypted.ciphertext);
}

async function hashHex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function makeEventHash({ timestamp, actor, action, previousHash }) {
  return hashHex(encoder.encode(`${timestamp}|${actor}|${action}|${previousHash}`));
}

async function createCustodyEvent(custody, actor, action) {
  const event = {
    timestamp: new Date().toISOString(),
    actor,
    action,
    previousHash: custody.at(-1)?.eventHash || 'GENESIS',
  };
  event.eventHash = await makeEventHash(event);
  return event;
}

async function extractMediaMetadata(file) {
  if (file.type.startsWith('image/')) {
    try {
      const bitmap = await createImageBitmap(file);
      const dimensions = `${bitmap.width} × ${bitmap.height} px`;
      bitmap.close();
      return { dimensions };
    } catch {
      return {};
    }
  }
  if (file.type.startsWith('audio/') || file.type.startsWith('video/')) {
    const element = document.createElement(file.type.startsWith('audio/') ? 'audio' : 'video');
    const url = URL.createObjectURL(file);
    const media = await new Promise((resolve) => {
      const finish = (result) => resolve(result);
      element.onloadedmetadata = () => finish({
        dimensions: element.videoWidth && element.videoHeight ? `${element.videoWidth} × ${element.videoHeight} px` : undefined,
        duration: Number.isFinite(element.duration) ? `${Math.floor(element.duration / 60)}:${String(Math.floor(element.duration % 60)).padStart(2, '0')}` : undefined,
      });
      element.onerror = () => finish({});
      element.src = url;
    });
    URL.revokeObjectURL(url);
    element.removeAttribute('src');
    return media;
  }
  if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
    const header = decoder.decode(await file.slice(0, 16).arrayBuffer());
    const version = header.match(/%PDF-(\d\.\d)/)?.[1];
    return version ? { pdfVersion: version } : {};
  }
  return {};
}

export async function saveEvidence(database, { file, caseId, custodian }) {
  const key = await getEncryptionKey(database);
  const fileBytes = await file.arrayBuffer();
  const metadata = {
    name: file.name,
    type: file.type,
    size: file.size,
    lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : new Date().toISOString(),
    sha256: await hashHex(fileBytes),
    ...await extractMediaMetadata(file),
    custody: [],
  };
  metadata.custody.push(await createCustodyEvent([], custodian, 'Evidence received'));
  const [encryptedFile, encryptedMetadata] = await Promise.all([
    encryptBytes(key, fileBytes),
    encryptBytes(key, encoder.encode(JSON.stringify(metadata))),
  ]);
  const id = crypto.randomUUID();
  const record = { id, caseId, createdAt: new Date().toISOString(), file: encryptedFile, metadata: encryptedMetadata };
  await putRecord(database, 'records', record);
  return id;
}

export async function getCaseRecords(database, caseId) {
  const key = await getEncryptionKey(database);
  const storedRecords = await requestResult(database.transaction('records', 'readonly').objectStore('records').index('caseId').getAll(caseId));
  const records = await Promise.all(storedRecords.map(async (record) => {
    const metadataBytes = await decryptBytes(key, record.metadata);
    return { id: record.id, caseId: record.caseId, createdAt: record.createdAt, ...JSON.parse(decoder.decode(metadataBytes)) };
  }));
  return records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

export async function getCases(database) {
  const storedRecords = await requestResult(database.transaction('records', 'readonly').objectStore('records').getAll());
  return [...new Set(storedRecords.map((record) => record.caseId))].sort();
}

export async function addCustodyEvent(database, id, actor, action) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  metadata.custody.push(await createCustodyEvent(metadata.custody, actor, action));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function downloadEvidence(database, id) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const bytes = await decryptBytes(key, record.file);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  if (await hashHex(bytes) !== metadata.sha256) throw new Error('SHA-256 verification failed. The evidence was not released.');
  return new Blob([bytes], { type: metadata.type || 'application/octet-stream' });
}

export async function verifyCustody(custody) {
  let previousHash = 'GENESIS';
  for (const entry of custody) {
    if (entry.previousHash !== previousHash || await makeEventHash(entry) !== entry.eventHash) return false;
    previousHash = entry.eventHash;
  }
  return custody.length > 0;
}