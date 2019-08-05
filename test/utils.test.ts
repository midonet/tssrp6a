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

test("#bigIntegerToWordArray", (t) => {
  t.plan(7);
  const bigOne = BigInteger.ONE;
  let wordArray = bigIntegerToWordArray(bigOne);
  t.equals(1, wordArray.sigBytes);
  t.equals(1 << 24, wordArray.words[0], "One");

  const bigZero = BigInteger.ZERO;
  wordArray = bigIntegerToWordArray(bigZero);
  t.equals(1, wordArray.sigBytes);
  t.equals(0, wordArray.words[0], "Zero");

  t.deepEqual(
    { words: [0xff << 24], sigBytes: 1 },
    bigIntegerToWordArray(bigOne.negate()),
    "Negative values are partially supported",
  );

  const testNumber = new BigInteger("0102", 16);
  wordArray = bigIntegerToWordArray(testNumber);
  t.equals(2, wordArray.sigBytes, "Two bytes in 0x0102");
  t.equals(0x0102 << 16, wordArray.words[0]);
});

test("#bigIntegerToWordArray 5 bytes number", (t) => {
  t.plan(5);
  const numberHexStr = "7fff7effee";
  const testNumber = new BigInteger(numberHexStr, 16);
  t.equals(1, testNumber.signum(), "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in 0x${numberHexStr}`);
  t.equals(0x7fff7eff, wordArray.words[0], "First word is correct");
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});

test("#bigIntegerToWordArray 1 byte number", (t) => {
  t.plan(2);
  const numberHexStr = "ff";
  const testNumber = new BigInteger(numberHexStr, 16);
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(1, wordArray.sigBytes, `One byte in 0x${numberHexStr}`);
  t.equals(
    testNumber.intValue() << 24,
    wordArray.words[0],
    "First word is correct",
  );
});

test("#bigIntegerToWordArray 5 bytes number, big byte", (t) => {
  t.plan(5);
  const numberHexStr = "ffffffffee";
  const testNumber = new BigInteger(numberHexStr, 16);
  t.equals(1, testNumber.signum(), "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in 0x${numberHexStr}`);
  t.equals(
    new BigInteger("ffffffff", 16).intValue(),
    wordArray.words[0],
    "First word is correct",
  );
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});
