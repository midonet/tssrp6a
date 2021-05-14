import { SRPParameters } from "../src/parameters";
import { bigIntegerToWordArray, hashBitCount } from "../src/utils";
import { test } from "./tests";

test("existing hash", (t) => {
  t.doesNotThrow(() => new SRPParameters());
  t.end();
});

test("non-existing hash", (t) => {
  t.throws(
    () => new SRPParameters(undefined, undefined, "SHO-256" as any),
    /unknown hash/i,
  );
  t.end();
});

test("hash bit count", (t) => {
  t.plan(7);
  const expectedBitSize = [160, 224, 256, 384, 512, 512, 160];
  Object.keys(SRPParameters.H).map((key, idx) => {
    const parameters = new SRPParameters(
      SRPParameters.N["2048"],
      BigInt([2]),
      SRPParameters.H[key],
    );
    t.equals(expectedBitSize[idx], hashBitCount(parameters.H), key);
  });
});

test("Size of N is correct", (t) => {
  t.plan(1);
  // Yes, the 256 bits number is actually 257 bits number
  // https://groups.google.com/forum/#!topic/clipperz/DJFqZYHv2qk
  const expectedSizeInBytes: number[] = [33, 64, 96, 128, 192, 256];
  const actualSizeInBytes: number[] = new Array(6).fill(0);
  Object.keys(SRPParameters.N).map((key, idx) => {
    actualSizeInBytes[idx] = bigIntegerToWordArray(
      SRPParameters.N[key],
    ).sigBytes;
  });
  actualSizeInBytes.sort((x, y) => x - y);
  t.deepEqual(expectedSizeInBytes, actualSizeInBytes, "N sizes are correct");
});
