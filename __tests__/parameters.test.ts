import { test } from "../../../test/util";
import { SRPParameters } from "../parameters";

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
