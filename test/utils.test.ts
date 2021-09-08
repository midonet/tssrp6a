import bigInt from "big-integer";
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
    const bn = bigInt(n, 16);
    t.true(arrayBufferToBigInt(bigIntToArrayBuffer(bn)).equals(bn), `${n}`);
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
  const routines = new SRPRoutines();
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
  t.plan(8);
  let arrayBuffer = bigIntToArrayBuffer(bigInt.one);
  let u8 = new Uint8Array(arrayBuffer);
  t.equals(1, arrayBuffer.byteLength);
  t.equals(1, u8[0], "One");

  arrayBuffer = bigIntToArrayBuffer(bigInt.zero);
  u8 = new Uint8Array(arrayBuffer);
  t.equals(1, arrayBuffer.byteLength);
  t.equals(0, u8[0], "Zero");

  t.deepLooseEqual(
    Uint8Array.from([0xff]),
    new Uint8Array(bigIntToArrayBuffer(bigInt.minusOne)),
    "Negative values are partially supported",
  );

  const testNumber = bigInt("0102", 16);
  arrayBuffer = bigIntToArrayBuffer(testNumber);
  u8 = new Uint8Array(arrayBuffer);
  t.equals(2, arrayBuffer.byteLength, "Two bytes in 0x0102");
  t.equals(1, u8[0]);
  t.equals(2, u8[1]);
});

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
  const testHashArray = bigIntToArrayBuffer(bigInt.one);
  t.equal(1, testHashArray.byteLength);

  const paddedLibArray = padStartArrayBuffer(testHashArray, 64);
  t.equals(64, paddedLibArray.byteLength);
  const expectedArray = new Array(64).fill(0);
  expectedArray[63] = 1;
  t.deepEqual(Uint8Array.from(expectedArray), new Uint8Array(paddedLibArray));
});
