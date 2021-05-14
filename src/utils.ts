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
 * @param arrayBuffer - ArrayBuffer to pad
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export const padStartArrayBuffer = (
  arrayBuffer: ArrayBuffer,
  targetLength: number,
): ArrayBuffer => {
  const u8 = new Uint8Array(arrayBuffer);
  if (u8.length < targetLength) {
    const tmp = new Uint8Array(targetLength);
    tmp.fill(0, 0, targetLength - u8.length);
    tmp.set(u8, targetLength - u8.length);
    return tmp;
  }
  return u8;
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
    padStartArrayBuffer(arrayBuffer, targetLen),
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

export async function createVerifier(
  routines: SRPRoutines,
  I: string,
  s: bigint,
  P: string,
): Promise<bigint> {
  if (!I || !I.trim()) {
    throw new Error("Identity (I) must not be null or empty.");
  }

  if (!s) {
    throw new Error("Salt (s) must not be null.");
  }

  if (!P) {
    throw new Error("Password (P) must not be null");
  }

  const x = await routines.computeX(I, s, P);

  return routines.computeVerifier(x);
}

export interface IVerifierAndSalt {
  v: bigint;
  s: bigint;
}

export async function createVerifierAndSalt(
  routines: SRPRoutines,
  I: string,
  P: string,
  sBytes?: number,
): Promise<IVerifierAndSalt> {
  const s = await routines.generateRandomSalt(sBytes);

  return {
    s,
    v: await createVerifier(routines, I, s, P),
  };
}

export const hashBitCount = async (
  parameters: SRPParameters,
): Promise<number> =>
  (await hash(parameters, bigIntToArrayBuffer(BigInt(1)))).byteLength << 3; // TODO make sure this still works

const generateRandom = (numBytes: number): ArrayBuffer => {
  const u8 = new Uint8Array(numBytes);
  crypto.getRandomValues(u8);
  return u8.buffer;
};
