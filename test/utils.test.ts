import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import {
  arrayBufferToBigInt,
  bigIntToArrayBuffer,
  createVerifier,
  generateRandomBigInt,
  generateRandomString,
  padStartArrayBuffer,
  stringToArrayBuffer,
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
    t.equals(arrayBufferToBigInt(bigIntToArrayBuffer(bn)), bn, `${n}`);
  });
});

test("#stringToArrayBuffer", (t) => {
  t.plan(3);
  const testString = "0123456";
  const hashArray = stringToArrayBuffer(testString);
  const charCodes: number[] = [];
  for (let i = 0; i < testString.length; ++i) {
    charCodes.push(testString.charCodeAt(i));
  }
  t.equals(testString.length, hashArray.byteLength, "Array size");
  t.deepEqual(
    Uint8Array.from(charCodes),
    new Uint8Array(hashArray),
    "Array values",
  );
  t.equals(stringToArrayBuffer("").byteLength, 0, "Empty string, empty array");
});

test("#createVerifierHexSalt errors", async (t) => {
  const routines = new SRPRoutines(new SRPParameters());
  const salt = generateRandomBigInt();
  await t.rejects(() => createVerifier(routines, "", salt, "password"));
  await t.rejects(() => createVerifier(routines, " ", salt, "password"));
  await t.rejects(() =>
    createVerifier(routines, "identifier", null!, "password"),
  );
  await t.rejects(() => createVerifier(routines, "identifier", salt, ""));
  t.end();
});

test("#bigIntToArrayBuffer", (t) => {
  t.plan(5);
  let arrayBuffer = bigIntToArrayBuffer(ONE);
  let u8 = new Uint8Array(arrayBuffer);
  t.equals(1, arrayBuffer.byteLength);
  t.equals(1, u8[0], "One");

  arrayBuffer = bigIntToArrayBuffer(ZERO);
  u8 = new Uint8Array(arrayBuffer);
  t.equals(1, arrayBuffer.byteLength);
  t.equals(0, u8[0], "Zero");

  t.deepLooseEqual(
    Uint8Array.from([0xff]),
    new Uint8Array(bigIntToArrayBuffer(-ONE)),
    "Negative values are partially supported",
  );

  /* const testNumber = BigInt("0x0102");
  arrayBuffer = bigIntToArrayBuffer(testNumber);
  u8 = new Uint8Array(arrayBuffer);
  t.equals(2, arrayBuffer.byteLength, "Two bytes in 0x0102");
  t.equals(0x0102 << 16, u8[0]); */
});

/*
test("#bigIntToArrayBuffer 5 bytes number", (t) => {
  t.plan(5);
  const numberHexStr = "7fff7effee";
  const testNumber = BigInt(`0x${numberHexStr}`);
  t.true(testNumber > 0, "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntToArrayBuffer(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in ${numberHexStr}`);
  t.equals(0x7fff7eff, wordArray.words[0], "First word is correct");
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});

test("#bigIntToArrayBuffer 1 byte number", (t) => {
  t.plan(2);
  const numberHexStr = "0xff";
  const testNumber = BigInt(numberHexStr);
  const wordArray = bigIntToArrayBuffer(testNumber);
  t.equals(1, wordArray.sigBytes, `One byte in {numberHexStr}`);
  t.equals(
    Number(testNumber) << 24,
    wordArray.words[0],
    "First word is correct",
  );
});

test("#bigIntToArrayBuffer 5 bytes number, big byte", (t) => {
  t.plan(4);
  const numberHexStr = "ffffffffee";
  const testNumber = BigInt(`0x${numberHexStr}`);
  t.true(testNumber > 0, "The number is positive");
  t.equals(
    numberHexStr,
    testNumber.toString(16),
    "toString() returns the same string",
  );
  const wordArray = bigIntToArrayBuffer(testNumber);
  t.equals(5, wordArray.sigBytes, `Five bytes in ${numberHexStr}`);
  t.equals(0xee << 24, wordArray.words[1], "Second word is correct");
});*/

test("#paddArray", (t) => {
  t.plan(6);
  const nums: number[] = [1, 2, 3];
  const testHashArray = new Uint8Array(nums);
  t.deepLooseEqual(
    testHashArray,
    new Uint8Array(padStartArrayBuffer(testHashArray.buffer, 2)),
    "Same array for small target size",
  );
  t.deepLooseEqual(
    testHashArray,
    new Uint8Array(padStartArrayBuffer(testHashArray.buffer, 3)),
    "Same array for small target size",
  );

  const paddedLibArray = padStartArrayBuffer(testHashArray, 4);
  t.equals(4, paddedLibArray.byteLength);
  t.deepEqual(Uint8Array.from([0, 1, 2, 3]), new Uint8Array(paddedLibArray));

  const paddedLibArray2 = padStartArrayBuffer(testHashArray, 10);
  t.equals(10, paddedLibArray2.byteLength);
  t.deepEqual(
    Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1, 2, 3]),
    new Uint8Array(paddedLibArray2),
  );
});

test("#paddArray 1 byte", (t) => {
  t.plan(3);
  const testHashArray = bigIntToArrayBuffer(ONE);
  t.equal(1, testHashArray.byteLength);

  const paddedLibArray = padStartArrayBuffer(testHashArray, 64);
  t.equals(64, paddedLibArray.byteLength);
  const expectedArray = new Array(64).fill(0);
  expectedArray[63] = 1;
  t.deepEqual(Uint8Array.from(expectedArray), new Uint8Array(paddedLibArray));
});
