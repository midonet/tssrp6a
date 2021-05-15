import { HashFunction } from "./parameters";

interface CompatibleCrypto {
  hashFunctions: { [key: string]: HashFunction };
  randomBytes: (array: Uint8Array) => Uint8Array;
}

export let crossEnvCrypto: CompatibleCrypto;

try {
  const webcrypto =
    (typeof window !== "undefined" && window.crypto) ||
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require("crypto").webcrypto; // Node v15+ has webcrypto built in, lets use that if we can

  if (webcrypto) {
    if (!webcrypto.subtle) {
      throw new Error(
        "Crypto.Subtle is undefined. Make sure you are using HTTPS in a compatible browser.",
      );
    }
    const digestFunctionToHashFunction =
      (algorithm: AlgorithmIdentifier) => (data: ArrayBuffer) =>
        webcrypto.subtle.digest(algorithm, data);
    crossEnvCrypto = {
      randomBytes: webcrypto.getRandomValues,
      hashFunctions: {
        SHA1: digestFunctionToHashFunction("SHA-1"),
        SHA256: digestFunctionToHashFunction("SHA-256"),
        SHA384: digestFunctionToHashFunction("SHA-384"),
        SHA512: digestFunctionToHashFunction("SHA-512"),
      },
    };
  } else {
    // otherwise lets use node's crypto
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require("crypto");
    const nodeCreateHashToHashFunction =
      (algorithm: AlgorithmIdentifier) => (data: ArrayBuffer) =>
        nodeCrypto.createHash(algorithm).update(data).digest().buffer;

    crossEnvCrypto = {
      randomBytes: nodeCrypto.randomFillSync,
      hashFunctions: {
        SHA1: nodeCreateHashToHashFunction("sha1"),
        SHA256: nodeCreateHashToHashFunction("sha256"),
        SHA384: nodeCreateHashToHashFunction("sha384"),
        SHA512: nodeCreateHashToHashFunction("sha512"),
      },
    };
  }
} catch (e) {
  console.error(e);
  throw new Error(
    "No suitable crypto library was found. You may need a polyfill.",
  );
}
