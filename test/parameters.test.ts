import { BigInteger } from "jsbn";
import { SRPParameters } from "../parameters";
import { hashBitCount } from "../utils";
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
      new BigInteger([2]),
      SRPParameters.H[key],
    );
    t.equals(expectedBitSize[idx], hashBitCount(parameters), key);
  });
});
