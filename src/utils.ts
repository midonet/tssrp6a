import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";

export const bigIntToArrayBuffer = (n: bigint): ArrayBuffer => {
  const hex = n.toString(16);
  const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
  const u8 = new Uint8Array(arrayBuffer);
  for (let i = 0; i < arrayBuffer.byteLength; i++) {
    u8[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return arrayBuffer;
};

export const arrayBufferToBigInt = (arrayBuffer: ArrayBuffer): bigint => {
  const hex: string[] = [];
  // we can't use map here because map will return Uint8Array which will screw up the parsing below
  new Uint8Array(arrayBuffer).forEach((i) => {
    hex.push(i.toString(16));
  });
  return BigInt(`0x${hex.join("")}`);
};

/**
 * Convert some string into ArrayBuffer.
 * @param str Any UTF8 string, like a username, email, or password
 */
export function stringToArrayBuffer(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer;
}

/**
 * Left pad ArrayBuffer with zeroes.
 * @param words
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export const padWordArray = (
  // TODO make sure this still works
  words: ArrayBuffer,
  targetLength: number,
): ArrayBuffer => {
  let result: ArrayBuffer = words;
  if (targetLength > words.byteLength) {
    const resultWords: number[] = new Array(ceilDiv4(targetLength)).fill(0);
    result = createHashWordArray(resultWords, targetLength);
    for (
      let dest = targetLength - words.sigBytes, src = 0;
      src < words.sigBytes;
      ++src, ++dest
    ) {
      setByte(result, dest, getByte(words, src));
    }
  }
  return result;
};

export function hash(
  parameters: SRPParameters,
  ...arrays: ArrayBuffer[]
): Promise<ArrayBuffer> {
  const length = arrays.reduce((p, c) => p + c.byteLength, 0);
  const target = new Uint8Array(length);
  for (let offset = 0, i = 0; i < arrays.length; i++) {
    target.set(new Uint8Array(arrays[i]), offset);
    offset += arrays[i].byteLength;
  }
  return parameters.H(target);
}

export function hashPadded(
  parameters: SRPParameters,
  targetLen: number,
  ...arrays: ArrayBuffer[]
): Promise<ArrayBuffer> {
  const arraysPadded = arrays.map((arrayBuffer) =>
    padWordArray(arrayBuffer, targetLen),
  );
  return hash(parameters, ...arraysPadded);
}

/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export function generateRandomString(characterCount: number = 10) {
  const u8 = new Uint8Array(characterCount / 2); // each byte has 2 hex digits
  crypto.getRandomValues(u8);
  return u8.reduce((str, i) => str + i.toString(16), "");
}

export function generateRandomBigInt(numBytes: number = 16): bigint {
  return arrayBufferToBigInt(generateRandom(numBytes));
}

export function createVerifier(
  routines: SRPRoutines,
  I: string,
  s: bigint,
  P: string,
): bigint {
  if (!I || !I.trim()) {
    throw new Error("Identity (I) must not be null or empty.");
  }

  if (!s) {
    throw new Error("Salt (s) must not be null.");
  }

  if (!P) {
    throw new Error("Password (P) must not be null");
  }

  const x = routines.computeX(I, s, P);

  return routines.computeVerifier(x);
}

export interface IVerifierAndSalt {
  v: bigint;
  s: bigint;
}

export function createVerifierAndSalt(
  routines: SRPRoutines,
  I: string,
  P: string,
  sBytes?: number,
): IVerifierAndSalt {
  const s = routines.generateRandomSalt(sBytes);

  return {
    s,
    v: createVerifier(routines, I, s, P),
  };
}

export const hashBitCount = async (
  parameters: SRPParameters,
): Promise<number> =>
  (await hash(parameters, bigIntToArrayBuffer(BigInt(1)))).byteLength << 3; // TODO make sure this still works

function ceilDiv4(x: number) {
  return (x + 3) >>> 2;
}

/**
 * Return the number of bits the byte should be shifted to occupy given position in 4 bytes integer.
 * @param byteNum The number of byte in big endian order. Can be only 0, 1, 2 or 3
 */
function byteShift(byteNum: number): number {
  return (3 - byteNum) << 3;
}

function getByte(array: HashWordArray, idx: number): number {
  // TODO
  return (array.words[idx >>> 2] >>> byteShift(idx & 3)) & 0xff;
}

function setByte(array: HashWordArray, idx: number, byteValue: number): void {
  // TODO
  array.words[idx >>> 2] &= ~(0xff << byteShift(idx & 3));
  array.words[idx >>> 2] |= (byteValue & 0xff) << byteShift(idx & 3);
}

const generateRandom = (numBytes: number): ArrayBuffer => {
  const u8 = new Uint8Array(numBytes);
  crypto.getRandomValues(u8);
  return u8.buffer;
};
