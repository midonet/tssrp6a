import { HashFunction } from "./parameters";
interface CompatibleCrypto {
    hashFunctions: {
        [key: string]: HashFunction;
    };
    randomBytes: (array: Uint8Array) => Uint8Array;
}
export declare let crossEnvCrypto: CompatibleCrypto;
export {};
