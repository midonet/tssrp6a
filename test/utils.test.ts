import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import {
  arrayBufferToBigInt,
  bigIntToArrayBuffer,
  createVerifier,
  generateRandomBigInt,
  generateRandomString,
  modPow,
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
  t.plan(8);
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

  const testNumber = BigInt("0x0102");
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
  const testHashArray = bigIntToArrayBuffer(ONE);
  t.equal(1, testHashArray.byteLength);

  const paddedLibArray = padStartArrayBuffer(testHashArray, 64);
  t.equals(64, paddedLibArray.byteLength);
  const expectedArray = new Array(64).fill(0);
  expectedArray[63] = 1;
  t.deepEqual(Uint8Array.from(expectedArray), new Uint8Array(paddedLibArray));
});

test("#modPow valid inputs", (t) => {
  t.plan(10);

  const mod = BigInt(1000000007);
  t.equal(ONE, modPow(ONE, ZERO, mod), "1**0 == 1");
  t.equal(ONE, modPow(ONE, ONE, mod), "1**1 == 1");
  t.equal(ONE, modPow(ONE, BigInt(1000), mod), "1**1000 == 1");

  t.equal(ZERO, modPow(ZERO, ONE, mod), "0**1 == 0");
  t.equal(ONE, modPow(ZERO, ZERO, mod), "0**0 == 1");
  t.equal(ZERO, modPow(ZERO, BigInt(1024), mod), "0**1024 == 0");

  t.equal(
    BigInt(243),
    modPow(BigInt(3), BigInt(5), BigInt(244)),
    "3**5 == 243",
  );
  t.equal(ONE, modPow(BigInt(3), BigInt(5), BigInt(11)), "3**5 % 11 == 1");
  t.equal(BigInt(1024), modPow(BigInt(2), BigInt(10), mod), "2**10 == 1024");
  t.equal(
    BigInt("372410231729430638"),
    modPow(BigInt(2), BigInt(1023), BigInt("1223432564564235345")),
    "2**1023 % big number is correct",
  );
});

test("#modPow invalid inputs", (t) => {
  t.plan(6);

  t.throws(
    () => modPow(-ONE, ONE, ONE),
    /Invalid base/,
    "Invalid base, negative",
  );
  t.throws(
    () => modPow(ONE, -ONE, ONE),
    /Invalid power/,
    "Invalid power, negative",
  );
  t.throws(
    () => modPow(ONE, ONE, -ONE),
    /Invalid modulo/,
    "Invalid modulo, negative",
  );
  t.throws(
    () => modPow(ONE, ONE, ZERO),
    /Invalid modulo/,
    "Invalid modulo, zero",
  );
  t.throws(
    () => modPow(BigInt("-485734857638473853465873465"), ONE, ONE),
    /Invalid base/,
    "Invalid base, bit negative",
  );
  t.throws(() => modPow(-ONE, -ONE, -ONE), /Invalid base/, "All invalids");
});
