const HIVE_HEADER_SIZE = 4096;
const MAX_KEY_DEPTH = 64;
const MAX_KEYS = 100_000;
const MAX_VALUES_PER_KEY = 10_000;
const MAX_VALUE_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACTS = 2_000;
const ROT13 = (value) => value.replace(/[a-z]/gi, (character) => String.fromCharCode(
  character.charCodeAt(0) + (character.toLowerCase() <= 'm' ? 13 : -13),
));

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer || Object.prototype.toString.call(input) === '[object ArrayBuffer]') return new Uint8Array(input);
  throw new TypeError('Registry hive input must be an ArrayBuffer or byte array.');
}

class RegistryHive {
  constructor(input) {
    this.bytes = toBytes(input);
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.keyCount = 0;
    this.keys = [];
    this.warnings = [];
    if (this.bytes.length < HIVE_HEADER_SIZE + 32 || this.ascii(0, 4) !== 'regf') {
      throw new Error('The evidence is not a supported offline Windows registry hive (REGF).');
    }
    if (this.ascii(HIVE_HEADER_SIZE, 4) !== 'hbin') {
      throw new Error('The registry hive has no valid first hive bin.');
    }
    const rootOffset = this.u32(0x24);
    if (!rootOffset || rootOffset >= this.bytes.length - HIVE_HEADER_SIZE) {
      throw new Error('The registry hive root key offset is invalid.');
    }
    this.rootOffset = rootOffset;
  }

  bounds(offset, length) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
      || offset < 0 || length < 0 || offset + length > this.bytes.length) {
      throw new Error('The registry hive contains an out-of-range structure.');
    }
  }

  u16(offset) {
    this.bounds(offset, 2);
    return this.view.getUint16(offset, true);
  }

  u32(offset) {
    this.bounds(offset, 4);
    return this.view.getUint32(offset, true);
  }

  ascii(offset, length) {
    this.bounds(offset, length);
    let result = '';
    for (let index = 0; index < length; index += 1) result += String.fromCharCode(this.bytes[offset + index]);
    return result;
  }

  cell(relativeOffset) {
    const physicalOffset = HIVE_HEADER_SIZE + relativeOffset;
    this.bounds(physicalOffset, 4);
    const signedLength = this.view.getInt32(physicalOffset, true);
    const length = Math.abs(signedLength);
    if (signedLength >= 0 || length < 8 || physicalOffset + length > this.bytes.length) {
      throw new Error('The registry hive references an invalid or unallocated cell.');
    }
    return { start: physicalOffset + 4, end: physicalOffset + length };
  }

  utf16(offset, length) {
    this.bounds(offset, length);
    return new TextDecoder('utf-16le', { fatal: false }).decode(this.bytes.subarray(offset, offset + length)).replace(/\0+$/, '');
  }

  cellName(relativeOffset) {
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2) !== 'nk') throw new Error('A registry subkey does not reference a key node.');
    if (cell.start + 0x50 > cell.end) throw new Error('A registry key node is truncated.');
    const flags = this.u16(cell.start + 2);
    const nameLength = this.u16(cell.start + 0x4c);
    if (cell.start + 0x50 + nameLength > cell.end) throw new Error('A registry key name exceeds its cell.');
    return (flags & 0x20)
      ? this.ascii(cell.start + 0x50, nameLength)
      : this.utf16(cell.start + 0x50, nameLength);
  }

  subkeyOffsets(listOffset, depth = 0, visited = new Set()) {
    if (!listOffset || depth > 16 || visited.has(listOffset)) return [];
    visited.add(listOffset);
    const cell = this.cell(listOffset);
    const signature = this.ascii(cell.start, 2);
    const count = this.u16(cell.start + 2);
    if (count > MAX_KEYS) throw new Error('The registry hive subkey index is too large.');
    const offsets = [];
    if (signature === 'ri') {
      if (cell.start + 4 + count * 4 > cell.end) throw new Error('The registry subkey index is truncated.');
      for (let index = 0; index < count; index += 1) {
        offsets.push(...this.subkeyOffsets(this.u32(cell.start + 4 + index * 4), depth + 1, visited));
      }
      return offsets;
    }
    if (signature !== 'li' && signature !== 'lf' && signature !== 'lh') return [];
    const entrySize = signature === 'li' ? 4 : 8;
    if (cell.start + 4 + count * entrySize > cell.end) throw new Error('The registry subkey index is truncated.');
    for (let index = 0; index < count; index += 1) {
      offsets.push(this.u32(cell.start + 4 + index * entrySize));
    }
    return offsets;
  }

  valueData(relativeOffset) {
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2) !== 'vk') throw new Error('A registry value list does not reference a value cell.');
    if (cell.start + 0x14 > cell.end) throw new Error('A registry value cell is truncated.');
    const nameLength = this.u16(cell.start + 2);
    const encodedLength = this.u32(cell.start + 4);
    const dataLength = encodedLength & 0x7fffffff;
    const dataOffset = this.u32(cell.start + 8);
    const type = this.u32(cell.start + 0x0c);
    const flags = this.u16(cell.start + 0x10);
    const valueName = nameLength
      ? ((flags & 1) ? this.ascii(cell.start + 0x14, nameLength) : this.utf16(cell.start + 0x14, nameLength))
      : '(Default)';
    if (cell.start + 0x14 + (flags & 1 ? nameLength : nameLength * 2) > cell.end) {
      throw new Error('A registry value name exceeds its cell.');
    }
    if (dataLength > MAX_VALUE_BYTES) throw new Error(`Registry value "${valueName}" exceeds the parser size limit.`);
    let bytes;
    if (encodedLength & 0x80000000) {
      if (dataLength > 4) throw new Error(`Registry value "${valueName}" has an invalid inline data length.`);
      bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, dataOffset, true);
      bytes = bytes.subarray(0, dataLength);
    } else if (dataLength === 0) {
      bytes = new Uint8Array();
    } else {
      const dataCell = this.cell(dataOffset);
      if (dataCell.start + dataLength > dataCell.end) throw new Error(`Registry value "${valueName}" exceeds its data cell.`);
      bytes = this.bytes.slice(dataCell.start, dataCell.start + dataLength);
    }
    return { name: valueName, type, data: this.decodeValue(type, bytes) };
  }

  decodeValue(type, bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (type === 1 || type === 2 || type === 6) return new TextDecoder('utf-16le').decode(bytes).replace(/\0+$/, '');
    if (type === 7) return new TextDecoder('utf-16le').decode(bytes).split('\0').filter(Boolean);
    if (type === 4 && bytes.length >= 4) return view.getUint32(0, true);
    if (type === 5 && bytes.length >= 4) return view.getUint32(0, false);
    if (type === 11 && bytes.length >= 8) return view.getBigUint64(0, true).toString();
    return {
      byteLength: bytes.length,
      hexPreview: Array.from(bytes.subarray(0, 64), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      truncated: bytes.length > 64,
    };
  }

  valuesAt(valueCount, valueListOffset) {
    if (valueCount > MAX_VALUES_PER_KEY) throw new Error('A registry key contains too many values.');
    if (!valueCount) return [];
    const list = this.cell(valueListOffset);
    if (list.start + valueCount * 4 > list.end) throw new Error('A registry value list is truncated.');
    return Array.from({ length: valueCount }, (_, index) => this.valueData(this.u32(list.start + index * 4)));
  }

  readKey(relativeOffset, parentPath = '', depth = 0, ancestors = new Set()) {
    if (depth > MAX_KEY_DEPTH) {
      this.warnings.push(`Key traversal stopped at the ${MAX_KEY_DEPTH}-level depth limit.`);
      return;
    }
    if (this.keyCount >= MAX_KEYS) {
      this.warnings.push(`Key traversal stopped at the ${MAX_KEYS}-key safety limit.`);
      return;
    }
    if (ancestors.has(relativeOffset)) throw new Error('The registry hive contains a cyclic key tree.');
    this.keyCount += 1;
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2) !== 'nk') throw new Error('The registry hive root does not reference a key node.');
    if (cell.start + 0x50 > cell.end) throw new Error('A registry key node is truncated.');
    const name = this.cellName(relativeOffset);
    const path = parentPath ? `${parentPath}\\${name}` : name;
    const subkeyCount = this.u32(cell.start + 0x18);
    const subkeyListOffset = this.u32(cell.start + 0x1c);
    const valueCount = this.u32(cell.start + 0x28);
    const valueListOffset = this.u32(cell.start + 0x2c);
    const values = this.valuesAt(valueCount, valueListOffset);
    this.keys.push({ path, values });
    const childOffsets = this.subkeyOffsets(subkeyListOffset);
    if (subkeyCount && childOffsets.length < subkeyCount) {
      this.warnings.push(`Some subkeys were unavailable under ${path}.`);
    }
    const nextAncestors = new Set(ancestors).add(relativeOffset);
    for (const childOffset of childOffsets.slice(0, subkeyCount)) {
      this.readKey(childOffset, path, depth + 1, nextAncestors);
    }
  }

  parse() {
    this.readKey(this.rootOffset);
    return this.keys;
  }
}

function artifact(type, key, values) {
  return { type, keyPath: key.path, values };
}

function extractArtifacts(keys, warnings) {
  const results = [];
  const add = (type, key, values) => {
    if (!values.length) return;
    if (results.length >= MAX_ARTIFACTS) {
      if (!warnings.includes(`Artifact extraction stopped at the ${MAX_ARTIFACTS}-artifact safety limit.`)) {
        warnings.push(`Artifact extraction stopped at the ${MAX_ARTIFACTS}-artifact safety limit.`);
      }
      return;
    }
    results.push(artifact(type, key, values));
  };
  const value = (key, name) => key.values.find((entry) => entry.name.toLowerCase() === name.toLowerCase())?.data;
  const matches = (key, expression) => expression.test(key.path);

  for (const key of keys) {
    if (matches(key, /\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?$/i)) {
      add('Startup command', key, key.values);
    }
    if (matches(key, /\\Internet Explorer\\TypedURLs$/i)) {
      add('Typed URL', key, key.values);
    }
    if (matches(key, /\\Explorer\\RecentDocs(?:\\.*)?$/i) && key.values.length) {
      add('Recent documents', key, key.values);
    }
    if (matches(key, /\\UserAssist\\\{[^}]+\}\\Count$/i) && key.values.length) {
      add('UserAssist execution entry', key, key.values.map((entry) => ({
        ...entry,
        name: ROT13(entry.name),
      })));
    }
    if (matches(key, /\\Enum\\USBSTOR(?:\\.*)?$/i)) {
      add('USB storage device', key, key.values);
    }
    if (matches(key, /\\MountedDevices$/i)) {
      add('Mounted device', key, key.values);
    }
    if (matches(key, /\\ControlSet\d{3}\\Services\\[^\\]+$/i)) {
      add('Service configuration', key, key.values.filter((entry) => (
        ['ImagePath', 'DisplayName', 'Start', 'Type', 'ObjectName'].includes(entry.name)
      )));
    }
    if (matches(key, /\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\[^\\]+$/i)) {
      add('User profile', key, key.values.filter((entry) => ['ProfileImagePath', 'Flags', 'State'].includes(entry.name)));
    }
    if (matches(key, /\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$/i)) {
      add('Installed application', key, key.values.filter((entry) => (
        ['DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation'].includes(entry.name)
      )));
    }
    if (matches(key, /\\Microsoft\\Windows NT\\CurrentVersion$/i)) {
      add('Windows installation', key, key.values.filter((entry) => (
        ['ProductName', 'DisplayVersion', 'CurrentBuild', 'BuildLabEx', 'InstallDate', 'RegisteredOwner'].includes(entry.name)
      )));
    }
  }
  return results;
}

export function parseRegistryHive(input, filename = '') {
  const hive = new RegistryHive(input);
  const keys = hive.parse();
  const path = filename.toLowerCase();
  const hiveType = /(?:^|[\\/])system(?:\.hive)?$/.test(path) ? 'SYSTEM'
    : /(?:^|[\\/])software(?:\.hive)?$/.test(path) ? 'SOFTWARE'
      : /(?:^|[\\/])sam(?:\.hive)?$/.test(path) ? 'SAM'
        : /(?:^|[\\/])security(?:\.hive)?$/.test(path) ? 'SECURITY'
          : /(?:^|[\\/])ntuser\.dat$/.test(path) ? 'NTUSER.DAT'
            : /(?:^|[\\/])usrclass\.dat$/.test(path) ? 'UsrClass.dat' : 'Unknown';
  return {
    format: 'Windows Registry Hive (REGF)',
    hiveType,
    parsedAt: new Date().toISOString(),
    keyCount: hive.keyCount,
    artifacts: extractArtifacts(keys, hive.warnings),
    warnings: hive.warnings,
  };
}
