import { test } from "../../../test/util";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import {
  createVerifier,
  evenLengthHex,
  generateRandomBigInteger,
} from "../utils";
test("#evenLengthHex", (t) => {
  t.strictEqual("aa11", evenLengthHex("aa11"));
  t.strictEqual("0baa11", evenLengthHex("baa11"));
  t.strictEqual("", evenLengthHex(""));
  t.strictEqual("01", evenLengthHex("1"));
  t.end();
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
