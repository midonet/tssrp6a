import { HashFunction } from "./parameters";

const webcrypto: Crypto =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;

if (!webcrypto || !webcrypto.subtle) {
  throw new Error(
    "Crypto.Subtle is undefined. Make sure you are using HTTPS in a compatible browser.",
  );
}

export const randomBytes = webcrypto.getRandomValues.bind(webcrypto);

export const sha1: HashFunction = (data: ArrayBuffer) =>
  webcrypto.subtle.digest("SHA-1", data);

export const sha512: HashFunction = (data: ArrayBuffer) =>
  webcrypto.subtle.digest("SHA-512", data);
