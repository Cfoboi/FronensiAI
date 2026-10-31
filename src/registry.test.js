import { expect, test } from 'vitest';
import { parseRegistryHive } from './registry';

function makeHive() {
  const buffer = new Uint8Array(8192);
  const view = new DataView(buffer.buffer);
  let nextOffset = 32;
  const cells = new Map();
  const align = (value) => (value + 7) & ~7;
  const allocate = (bodyLength) => {
    const offset = nextOffset;
    const size = align(bodyLength + 4);
    nextOffset += size;
    cells.set(offset, { size, body: new Uint8Array(size - 4) });
    return offset;
  };
  const cellBody = (offset) => cells.get(offset).body;
  const put16 = (offset, position, value) => new DataView(cellBody(offset).buffer).setUint16(position, value, true);
  const put32 = (offset, position, value) => new DataView(cellBody(offset).buffer).setUint32(position, value, true);
  const writeCell = (offset) => {
    const cell = cells.get(offset);
    view.setInt32(4096 + offset, -cell.size, true);
    buffer.set(cell.body, 4096 + offset + 4);
  };
  const encodeUtf16 = (text) => {
    const bytes = new Uint8Array((text.length + 1) * 2);
    for (let index = 0; index < text.length; index += 1) {
      bytes[index * 2] = text.charCodeAt(index) & 0xff;
      bytes[index * 2 + 1] = text.charCodeAt(index) >> 8;
    }
    return bytes;
  };
  const names = ['Software', 'Microsoft', 'Windows', 'CurrentVersion', 'Run'];
  const keys = names.map((name) => ({ name, offset: allocate(0x50 + name.length) }));
  const commandBytes = encodeUtf16('C:\\Temp\\sample.exe\0');
  const dataOffset = allocate(commandBytes.length);
  cellBody(dataOffset).set(commandBytes);
  const valueName = 'Updater';
  const valueOffset = allocate(0x14 + valueName.length);
  const valueListOffset = allocate(8);
  const subkeyLists = keys.slice(0, -1).map(() => allocate(8));

  keys.forEach(({ name, offset }, index) => {
    const body = cellBody(offset);
    body.set([0x6e, 0x6b], 0);
    put16(offset, 2, 0x20);
    const next = index < keys.length - 1 ? keys[index + 1].offset : 0;
    put32(offset, 0x18, next ? 1 : 0);
    put32(offset, 0x1c, index < subkeyLists.length ? subkeyLists[index] : 0);
    put32(offset, 0x28, index === keys.length - 1 ? 1 : 0);
    put32(offset, 0x2c, index === keys.length - 1 ? valueListOffset : 0);
    put16(offset, 0x4c, name.length);
    for (let nameIndex = 0; nameIndex < name.length; nameIndex += 1) {
      body[0x50 + nameIndex] = name.charCodeAt(nameIndex);
    }
  });

  keys.slice(0, -1).forEach((key, index) => {
    const listOffset = subkeyLists[index];
    const body = cellBody(listOffset);
    body.set([0x6c, 0x69], 0);
    put16(listOffset, 2, 1);
    put32(listOffset, 4, keys[index + 1].offset);
  });

  const valueBody = cellBody(valueOffset);
  valueBody.set([0x76, 0x6b], 0);
  put16(valueOffset, 2, valueName.length);
  put32(valueOffset, 4, commandBytes.length);
  put32(valueOffset, 8, dataOffset);
  put32(valueOffset, 0x0c, 1);
  put16(valueOffset, 0x10, 1);
  for (let index = 0; index < valueName.length; index += 1) valueBody[0x14 + index] = valueName.charCodeAt(index);

  put32(valueListOffset, 0, valueOffset);
  cells.forEach((_, offset) => writeCell(offset));
  buffer.set([0x72, 0x65, 0x67, 0x66], 0);
  view.setUint32(0x24, keys[0].offset, true);
  buffer.set([0x68, 0x62, 0x69, 0x6e], 4096);
  view.setUint32(4104, 4096, true);
  return buffer;
}

test('parses an offline REGF hive and extracts startup command artifacts', () => {
  const result = parseRegistryHive(makeHive(), 'SOFTWARE');

  expect(result).toMatchObject({
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    keyCount: 5,
    warnings: [],
    artifacts: [{
      type: 'Startup command',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      values: [{
        name: 'Updater',
        type: 1,
        data: 'C:\\Temp\\sample.exe',
      }],
    }],
  });
  expect(Date.parse(result.parsedAt)).not.toBeNaN();
});

test('rejects files that are not valid offline registry hives', () => {
  expect(() => parseRegistryHive(new Uint8Array(8192))).toThrow(/not a supported offline Windows registry hive/);
  const malformedHive = makeHive();
  malformedHive[4096] = 0;
  expect(() => parseRegistryHive(malformedHive)).toThrow(/no valid first hive bin/);
  expect(() => parseRegistryHive('invalid input')).toThrow(/ArrayBuffer or byte array/);
});
