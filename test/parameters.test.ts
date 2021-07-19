import { SRPRoutines } from "../src";
import { knownPrimeGroups } from "../src/parameters";
import { bigIntToArrayBuffer, hashBitCount } from "../src/utils";
import { test } from "./tests";

test("existing hash", (t) => {
  t.doesNotThrow(() => new SRPRoutines().H);
  t.end();
});

test("no hash function", (t) => {
  t.throws(() => new SRPRoutines(2048, null!).H);
  t.end();
});

test("hash bit count", async (t) => {
  t.plan(4);

  t.equals(await hashBitCount(new SRPRoutines(2048, "SHA-1").H), 160, "SHA-1");

  t.equals(
    await hashBitCount(new SRPRoutines(2048, "SHA-256").H),
    256,
    "SHA-256",
  );

  t.equals(
    await hashBitCount(new SRPRoutines(2048, "SHA-384").H),
    384,
    "SHA-384",
  );

  t.equals(
    await hashBitCount(new SRPRoutines(2048, "SHA-512").H),
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
