var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { bigIntToArrayBuffer, generateRandomBigInt, hash, hashPadded, stringToArrayBuffer, arrayBufferToBigInt, hashBitCount, modPow, } from "./utils.js";
/**
 * Default routines used for SRP calculation.
 *
 * These routines were implemented based on the Java Nimbus-SRP implementation.
 * This project can be found at https://bitbucket.org/connect2id/nimbus-srp
 * and the reference routine implementation at:
 * https://bitbucket.org/connect2id/nimbus-srp/src/c88fec8a6dcd46dacf1e031b52f9bffca902acf4/src/main/java/com/nimbusds/srp6/SRP6Routines.java
 */
export class SRPRoutines {
    constructor(parameters) {
        this.parameters = parameters;
    }
    hash(...as) {
        return hash(this.parameters, ...as);
    }
    hashPadded(...as) {
        const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
        return hashPadded(this.parameters, targetLength, ...as);
    }
    computeK() {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hashPadded(bigIntToArrayBuffer(this.parameters.primeGroup.N), bigIntToArrayBuffer(this.parameters.primeGroup.g)));
        });
    }
    generateRandomSalt(numBytes) {
        return __awaiter(this, void 0, void 0, function* () {
            const HBits = yield hashBitCount(this.parameters);
            // Recommended salt bytes is > than Hash output bytes. We default to twice
            // the bytes used by the hash
            const saltBytes = numBytes || (2 * HBits) / 8;
            return generateRandomBigInt(saltBytes);
        });
    }
    computeX(I, s, P) {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hash(bigIntToArrayBuffer(s), yield this.computeIdentityHash(I, P)));
        });
    }
    computeXStep2(s, identityHash) {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hash(bigIntToArrayBuffer(s), identityHash));
        });
    }
    computeIdentityHash(_, P) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.hash(stringToArrayBuffer(P));
        });
    }
    computeVerifier(x) {
        return modPow(this.parameters.primeGroup.g, x, this.parameters.primeGroup.N);
    }
    generatePrivateValue() {
        const numBits = Math.max(256, this.parameters.NBits);
        let bi;
        do {
            bi = generateRandomBigInt(numBits / 8) % this.parameters.primeGroup.N;
        } while (bi === BigInt(0));
        return bi;
    }
    computeClientPublicValue(a) {
        return modPow(this.parameters.primeGroup.g, a, this.parameters.primeGroup.N);
    }
    isValidPublicValue(value) {
        return value % this.parameters.primeGroup.N !== BigInt(0);
    }
    computeU(A, B) {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hashPadded(bigIntToArrayBuffer(A), bigIntToArrayBuffer(B)));
        });
    }
    computeClientEvidence(_I, _s, A, B, S) {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hash(bigIntToArrayBuffer(A), bigIntToArrayBuffer(B), bigIntToArrayBuffer(S)));
        });
    }
    computeServerEvidence(A, M1, S) {
        return __awaiter(this, void 0, void 0, function* () {
            return arrayBufferToBigInt(yield this.hash(bigIntToArrayBuffer(A), bigIntToArrayBuffer(M1), bigIntToArrayBuffer(S)));
        });
    }
    computeClientSessionKey(k, x, u, a, B) {
        const N = this.parameters.primeGroup.N;
        const exp = u * x + a;
        const tmp = (modPow(this.parameters.primeGroup.g, x, N) * k) % N;
        return modPow(B + N - tmp, exp, N);
    }
}
//# sourceMappingURL=routines.js.map