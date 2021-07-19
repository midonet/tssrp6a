const webcrypto: Crypto =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

if (!webcrypto || !webcrypto.subtle) {
  throw new Error(
    "Crypto.Subtle is undefined. Make sure you are using HTTPS in a compatible browser.",
  );
}

export const randomBytes = webcrypto.getRandomValues.bind(webcrypto);

export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
export type HashFunction = (data: ArrayBuffer) => Promise<ArrayBuffer>;

export const hashFunctions: Record<HashAlgorithm, HashFunction> = {
  "SHA-1": (data) => webcrypto.subtle.digest("SHA-1", data),
  "SHA-256": (data) => webcrypto.subtle.digest("SHA-256", data),
  "SHA-384": (data) => webcrypto.subtle.digest("SHA-384", data),
  "SHA-512": (data) => webcrypto.subtle.digest("SHA-512", data),
};
