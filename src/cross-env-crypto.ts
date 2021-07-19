const webcrypto: Crypto =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

if (!webcrypto || !webcrypto.subtle) {
  throw new Error(
    "Crypto.Subtle is undefined. Make sure you are using HTTPS in a compatible browser.",
  );
}

export const randomBytes = webcrypto.getRandomValues.bind(webcrypto);

export type HashFunction = (data: ArrayBuffer) => Promise<ArrayBuffer>;

export const sha1: HashFunction = (data) =>
  webcrypto.subtle.digest("SHA-1", data);

export const sha256: HashFunction = (data) =>
  webcrypto.subtle.digest("SHA-256", data);

export const sha384: HashFunction = (data) =>
  webcrypto.subtle.digest("SHA-384", data);

export const sha512: HashFunction = (data) =>
  webcrypto.subtle.digest("SHA-512", data);
