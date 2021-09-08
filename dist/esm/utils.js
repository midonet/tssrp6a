var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { crossEnvCrypto } from "./cross-env-crypto.js";
const ZERO = BigInt(0);
const ONE = BigInt(1);
const TWO = BigInt(2);
export const bigIntToArrayBuffer = (n) => {
    const hex = n.toString(16);
    const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
    const u8 = new Uint8Array(arrayBuffer);
    let offset = 0;
    // handle toString(16) not padding
    if (hex.length % 2 !== 0) {
        u8[0] = parseInt(hex[0], 16);
        offset = 1;
    }
    for (let i = 0; i < arrayBuffer.byteLength; i++) {
        u8[i + offset] = parseInt(hex.slice(2 * i + offset, 2 * i + 2 + offset), 16);
    }
    return arrayBuffer;
};
export const arrayBufferToBigInt = (arrayBuffer) => {
    const hex = [];
    // we can't use map here because map will return Uint8Array which will screw up the parsing below
    new Uint8Array(arrayBuffer).forEach((i) => {
        hex.push(("0" + i.toString(16)).slice(-2)); // i.toString(16) will transform 01 to 1, so we add it back on and slice takes the last two chars
    });
    return BigInt(`0x${hex.join("")}`);
};
/**
 * Convert some string into ArrayBuffer.
 * @param str Any UTF8 string, like a username, email, or password
 */
export function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str).buffer;
}
/**
 * Left pad ArrayBuffer with zeroes.
 * @param arrayBuffer - ArrayBuffer to pad
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export const padStartArrayBuffer = (arrayBuffer, targetLength) => {
    const u8 = new Uint8Array(arrayBuffer);
    if (u8.length < targetLength) {
        const tmp = new Uint8Array(targetLength);
        tmp.fill(0, 0, targetLength - u8.length);
        tmp.set(u8, targetLength - u8.length);
        return tmp;
    }
    return u8;
};
export function hash(parameters, ...arrays) {
    const length = arrays.reduce((p, c) => p + c.byteLength, 0);
    const target = new Uint8Array(length);
    for (let offset = 0, i = 0; i < arrays.length; i++) {
        target.set(new Uint8Array(arrays[i]), offset);
        offset += arrays[i].byteLength;
    }
    return parameters.H(target);
}
export function hashPadded(parameters, targetLen, ...arrays) {
    const arraysPadded = arrays.map((arrayBuffer) => padStartArrayBuffer(arrayBuffer, targetLen));
    return hash(parameters, ...arraysPadded);
}
/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export function generateRandomString(characterCount = 10) {
    const u8 = new Uint8Array(Math.ceil(Math.ceil(characterCount / 2))); // each byte has 2 hex digits
    crossEnvCrypto.randomBytes(u8);
    return u8
        .reduce((str, i) => {
        const hex = i.toString(16).toString();
        if (hex.length === 1) {
            return str + "0" + hex;
        }
        return str + hex;
    }, "")
        .slice(0, characterCount); // so we don't go over when characterCount is odd
}
export function generateRandomBigInt(numBytes = 16) {
    return arrayBufferToBigInt(generateRandom(numBytes));
}
export function createVerifier(routines, I, s, P) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!I || !I.trim()) {
            throw new Error("Identity (I) must not be null or empty.");
        }
        if (!s) {
            throw new Error("Salt (s) must not be null.");
        }
        if (!P) {
            throw new Error("Password (P) must not be null");
        }
        const x = yield routines.computeX(I, s, P);
        return routines.computeVerifier(x);
    });
}
export function createVerifierAndSalt(routines, I, P, sBytes) {
    return __awaiter(this, void 0, void 0, function* () {
        const s = yield routines.generateRandomSalt(sBytes);
        return {
            s,
            v: yield createVerifier(routines, I, s, P),
        };
    });
}
export const hashBitCount = (parameters) => __awaiter(void 0, void 0, void 0, function* () { return (yield hash(parameters, bigIntToArrayBuffer(BigInt(1)))).byteLength * 8; });
/**
 * Calculates (x**pow) % mod
 * @param x base, non negative big int.
 * @param pow power, non negative power.
 * @param mod modulo, positive modulo for division.
 */
export function modPow(x, pow, mod) {
    if (x < ZERO) {
        throw new Error("Invalid base: " + x.toString());
    }
    if (pow < ZERO) {
        throw new Error("Invalid power: " + pow.toString());
    }
    if (mod < ONE) {
        throw new Error("Invalid modulo: " + mod.toString());
    }
    let result = ONE;
    while (pow > ZERO) {
        if (pow % TWO == ONE) {
            result = (x * result) % mod;
            pow -= ONE;
        }
        else {
            x = (x * x) % mod;
            pow /= TWO;
        }
    }
    return result;
}
const generateRandom = (numBytes) => {
    const u8 = new Uint8Array(numBytes);
    crossEnvCrypto.randomBytes(u8);
    return u8.buffer;
};
//# sourceMappingURL=utils.js.map