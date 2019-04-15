import { BigInteger } from "jsbn";
import { hexToBytes } from "src/helpers/bytes";
import { test } from "../../../test/util";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import {
  anyToHexString,
  bigIntegerToHex,
  bytesToHex,
  createVerifierHexSalt,
  evenLengthHex,
  hexLeftPad,
} from "../utils";
test("#evenLengthHex", (t) => {
  t.strictEqual("aa11", evenLengthHex("aa11"));
  t.strictEqual("0baa11", evenLengthHex("baa11"));
  t.strictEqual("", evenLengthHex(""));
  t.strictEqual("01", evenLengthHex("1"));
  t.end();
});

test("#bytesToHex", (t) => {
  t.strictEqual("", bytesToHex(new Uint8Array(0)));
  t.strictEqual("0000", bytesToHex(new Uint8Array(2)));
  t.strictEqual(
    "0001022a646566ff",
    bytesToHex(new Uint8Array([0, 1, 2, 42, 100, 101, 102, 255])),
  );
  t.end();
});

test("#hexToBytes", (t) => {
  t.deepEqual([], hexToBytes(""));
  t.deepEqual([], hexToBytes("0"));
  t.deepEqual(
    [0, 1, 2, 42, 100, 101, 102, 255],
    hexToBytes("0001022a646566ff"),
  );
  t.end();
});

test("#bigIntegerToHex", (t) => {
  t.strictEqual("beef", bigIntegerToHex(new BigInteger("beef", 16)));
  t.end();
});

test("#hexLeftPad", (t) => {
  // t.strictEqual("beef", hexLeftPad(h("beef"), 1)); // TODO what should it do?
  t.strictEqual("beef", hexLeftPad("beef", 2));
  t.strictEqual("00beef", hexLeftPad("beef", 3));
  t.end();
});

test("#anyToHexString", (t) => {
  t.strictEqual("beef", anyToHexString("beef"));
  t.strictEqual("0bee", anyToHexString("bee"));
  t.strictEqual("beef", anyToHexString(new BigInteger("beef", 16)));
  t.strictEqual(
    "0001022a646566ff",
    anyToHexString(new Uint8Array([0, 1, 2, 42, 100, 101, 102, 255])),
  );
  t.throws(() => anyToHexString(12312 as any));
  t.end();
});

test("#createVerifierHexSalt errors", (t) => {
  const config = new SRPConfig(new SRPParameters(), (p) => new SRPRoutines(p));
  t.throws(() => createVerifierHexSalt(config, "", "salt", "password"));
  t.throws(() => createVerifierHexSalt(config, " ", "salt", "password"));
  t.throws(() => createVerifierHexSalt(config, "identifier", "", "password"));
  t.throws(() => createVerifierHexSalt(config, "identifier", "salt", ""));
  t.end();
});
