import { SRPParameters } from "../src/parameters";
import { bigIntToArrayBuffer, hashBitCount } from "../src/utils";
import { test } from "./tests";

test("existing hash", (t) => {
  t.doesNotThrow(() => new SRPParameters());
  t.end();
});

test("hash bit count", (t) => {
  t.plan(7);
  const expectedBitSize = [160, 224, 256, 384, 512, 512, 160];
  Object.keys(SRPParameters.H).map((key, idx) => {
    const parameters = new SRPParameters(
      SRPParameters.PrimeGroup[2048],
      SRPParameters.H[key],
    );
    t.equals(expectedBitSize[idx], hashBitCount(parameters), key);
  });
});

test("Size of N is correct", (t) => {
  t.plan(1);
  // Yes, the 256 bits number is actually 257 bits number
  // https://groups.google.com/forum/#!topic/clipperz/DJFqZYHv2qk
  const expectedSizeInBytes: number[] = [33, 64, 96, 128, 192, 256];
  const actualSizeInBytes: number[] = new Array(6).fill(0);
  Object.keys(SRPParameters.PrimeGroup).map((key, idx) => {
    actualSizeInBytes[idx] = bigIntToArrayBuffer(
      SRPParameters.PrimeGroup[key],
    ).byteLength;
  });
  actualSizeInBytes.sort((x, y) => x - y);
  t.deepEqual(expectedSizeInBytes, actualSizeInBytes, "N sizes are correct");
});
