import { sha1, sha512 } from "../src/cross-env-crypto";
import { knownPrimeGroups, SRPParameters } from "../src/parameters";
import { bigIntToArrayBuffer, hashBitCount } from "../src/utils";
import { test } from "./tests";

test("existing hash", (t) => {
  t.doesNotThrow(() => new SRPParameters());
  t.end();
});

test("no hash function", (t) => {
  t.throws(() => new SRPParameters(knownPrimeGroups[2048], null!));
  t.end();
});

test("hash bit count", async (t) => {
  t.plan(2);

  t.equals(
    await hashBitCount(new SRPParameters(knownPrimeGroups[2048], sha1)),
    160,
    "SHA-1",
  );

  t.equals(
    await hashBitCount(new SRPParameters(knownPrimeGroups[2048], sha512)),
    512,
    "SHA-512",
  );
});

test("Size of N is correct", (t) => {
  t.plan(1);
  const primeGroups = Object.keys(knownPrimeGroups).map((key) =>
    parseInt(key),
  ) as (keyof typeof knownPrimeGroups)[];
  // Yes, the 256 bits number is actually 257 bits number
  // https://groups.google.com/forum/#!topic/clipperz/DJFqZYHv2qk
  const expectedSizeInBytes: number[] = [128, 192, 256, 384, 512, 768, 1024];
  const actualSizeInBytes: number[] = new Array(primeGroups.length).fill(0);
  primeGroups.map((key, idx) => {
    actualSizeInBytes[idx] = bigIntToArrayBuffer(
      knownPrimeGroups[key].N,
    ).byteLength;
  });
  actualSizeInBytes.sort((x, y) => x - y);
  t.deepEqual(expectedSizeInBytes, actualSizeInBytes, "N sizes are correct");
});
