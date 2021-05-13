import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import {
  bigIntegerToWordArray,
  createHashWordArray,
  createVerifier,
  generateRandomBigInt,
  generateRandomString,
  padWordArray,
  stringToWordArray,
  wordArrayToBigInt,
} from "../src/utils";
import { test } from "./tests";

const ZERO = BigInt(0);
const ONE = BigInt(1);

test("#generateRandomString", (t) => {
  t.plan(2);
  t.equals(10, generateRandomString().length, "Default length");
  const actualLengths = new Array(32).fill(0);
  const expectedLengths = new Array(32).fill(0);
  for (let i = 0; i < 32; ++i) {
    expectedLengths[i] = i;
    actualLengths[i] = generateRandomString(i).length;
  }
  t.deepEqual(expectedLengths, actualLengths, "Strings lengths are correct");
});

test("#toFromBigIntegerConversions", (t) => {
  t.plan(3);
  ["aa11", "baa11", "1"].forEach((n) => {
    const bn = BigInt(`0x${n}`);
    t.equals(wordArrayToBigInt(bigIntegerToWordArray(bn)), bn, `${n}`);
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

  t.deepLooseEqual(
    { words: [], sigBytes: 0 },
    stringToWordArray(""),
    "Empty string, empty array",
  );
});

test("#createVerifierHexSalt errors", (t) => {
  const routines = new SRPRoutines(new SRPParameters());
  const salt = generateRandomBigInt();
  t.throws(() => createVerifier(routines, "", salt, "password"));
  t.throws(() => createVerifier(routines, " ", salt, "password"));
  t.throws(() => createVerifier(routines, "identifier", null!, "password"));
  t.throws(() => createVerifier(routines, "identifier", salt, ""));
  t.end();
});

test("#bigIntegerToWordArray", (t) => {
  t.plan(7);
  let wordArray = bigIntegerToWordArray(ONE);
  t.equals(1, wordArray.sigBytes);
  t.equals(1 << 24, wordArray.words[0], "One");

  wordArray = bigIntegerToWordArray(ZERO);
  t.equals(1, wordArray.sigBytes);
  t.equals(0, wordArray.words[0], "Zero");

  t.deepLooseEqual(
    { words: [0xff << 24], sigBytes: 1 },
    bigIntegerToWordArray(-ONE),
    "Negative values are partially supported",
  );

  const testNumber = BigInt("0x0102");
  wordArray = bigIntegerToWordArray(testNumber);
  t.equals(2, wordArray.sigBytes, "Two bytes in 0x0102");
  t.equals(0x0102 << 16, wordArray.words[0]);
});

test("#bigIntegerToWordArray 5 bytes number", (t) => {
  t.plan(5);
  const numberHexStr = "7fff7effee";
  const testNumber = BigInt(`0x${numberHexStr}`);
  t.true(testNumber > 0, "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in ${numberHexStr}`);
  t.equals(0x7fff7eff, wordArray.words[0], "First word is correct");
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});

test("#bigIntegerToWordArray 1 byte number", (t) => {
  t.plan(2);
  const numberHexStr = "0xff";
  const testNumber = BigInt(numberHexStr);
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(1, wordArray.sigBytes, `One byte in {numberHexStr}`);
  t.equals(
    Number(testNumber) << 24,
    wordArray.words[0],
    "First word is correct",
  );
});

test("#bigIntegerToWordArray 5 bytes number, big byte", (t) => {
  t.plan(4);
  const numberHexStr = "ffffffffee";
  const testNumber = BigInt(`0x${numberHexStr}`);
  t.true(testNumber > 0, "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntegerToWordArray(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in ${numberHexStr}`);
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});

test("#paddArray", (t) => {
  t.plan(6);
  const words: number[] = [1, 2, 3];
  const testHashArray = createHashWordArray(words, 12);
  t.equals(
    words,
    padWordArray(testHashArray, 10).words,
    "Same array for small target size",
  );
  t.equals(
    words,
    padWordArray(testHashArray, 12).words,
    "Same array for small target size",
  );

  const paddedLibArray = padWordArray(testHashArray, 16);
  t.equals(4, paddedLibArray.words.length);
  t.deepEqual([0, 1, 2, 3], paddedLibArray.words);

  const paddedLibArray2 = padWordArray(testHashArray, 15);
  t.equals(15, paddedLibArray2.sigBytes, "Array length is correct");
  t.deepEqual([0, 1 << 8, 2 << 8, 3 << 8], paddedLibArray2.words);
});

test("#paddArray 1 byte", (t) => {
  t.plan(3);
  const testHashArray = bigIntegerToWordArray(ONE);
  t.equal(1, testHashArray.sigBytes);

  const paddedLibArray = padWordArray(testHashArray, 256);
  t.equals(256, paddedLibArray.sigBytes);
  const expectedArray = new Array(64).fill(0);
  expectedArray[63] = 1;
  t.deepEqual(expectedArray, paddedLibArray.words);
});
