import { BigInteger } from "jsbn";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import {
  bigIntegerToWordArray,
  createVerifier,
  generateRandomBigInteger,
  stringToWordArray,
  wordArrayToBigInteger,
} from "../utils";
import { test } from "./tests";
test("#toFromBigIntegerConversions", (t) => {
  t.plan(3);
  ["aa11", "baa11", "1"].forEach((n) => {
    const bn = new BigInteger(n, 16);
    t.true(wordArrayToBigInteger(bigIntegerToWordArray(bn)).equals(bn), `${n}`);
  });
});

test("#stringToWordArray", (t) => {
  t.plan(3);
  const testString = "0123456";
  const hashArray = stringToWordArray(testString);
  const charCodes: number[] = [];
  for (let i = 0; i < testString.length; ++i) {
    charCodes.push(testString.charCodeAt(i));
  }
  t.equals(testString.length, hashArray.sigBytes, "Array size");
  t.deepEqual(
    [
      (charCodes[0] << 24) |
        (charCodes[1] << 16) |
        (charCodes[2] << 8) |
        charCodes[3],
      (charCodes[4] << 24) | (charCodes[5] << 16) | (charCodes[6] << 8),
    ],
    hashArray.words,
    "Array values",
  );

  t.deepEqual(
    { words: [], sigBytes: 0 },
    stringToWordArray(""),
    "Empty string, empty array",
  );
});

test("#createVerifierHexSalt errors", (t) => {
  const config = new SRPConfig(new SRPParameters(), (p) => new SRPRoutines(p));
  const salt = generateRandomBigInteger();
  t.throws(() => createVerifier(config, "", salt, "password"));
  t.throws(() => createVerifier(config, " ", salt, "password"));
  t.throws(() => createVerifier(config, "identifier", null!, "password"));
  t.throws(() => createVerifier(config, "identifier", salt, ""));
  t.end();
});
