import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { generateRandomBigInt, generateRandomString } from "../src/utils";
import { test } from "./tests";

test("#ParameterValidation1 Null/Undefined Identity", async (t) => {
  const session = new SRPClientSession(new SRPRoutines());
  await t.rejects(
    () => session.step1(null!, generateRandomString(16)),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation1 Empty Identity", async (t) => {
  const session = new SRPClientSession(new SRPRoutines());
  await t.rejects(() => session.step1("", generateRandomString(16)), /empty/i);
  t.end();
});

test("#ParameterValidation1 Null/Undefined password", async (t) => {
  const session = new SRPClientSession(new SRPRoutines());
  await t.rejects(
    () => session.step1(generateRandomString(16), null!),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation2 All correct", async (t) => {
  const session = await new SRPClientSession(new SRPRoutines()).step1("a", "b");
  await t.doesNotReject(() =>
    session.step2(generateRandomBigInt(16), generateRandomBigInt(16)),
  );
  t.end();
});

test("#ParameterValidation2 Null/Undefined salt", async (t) => {
  const session = await new SRPClientSession(new SRPRoutines()).step1("a", "b");
  await t.rejects(
    () => session.step2(null!, generateRandomBigInt(16)),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation2 Null/Undefined B", async (t) => {
  const session = await new SRPClientSession(new SRPRoutines()).step1("a", "b");
  await t.rejects(
    () => session.step2(generateRandomBigInt(16), null!),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation3 All correct", async (t) => {
  const session = await (
    await new SRPClientSession(new SRPRoutines()).step1("a", "b")
  ).step2(generateRandomBigInt(16), generateRandomBigInt(16));
  // It rejects because the fake values don't allow the verification to work
  await t.rejects(() => session.step3(generateRandomBigInt(16)), /bad server/i);
  t.end();
});

test("#ParameterValidation3 Null/Undefined M2", async (t) => {
  const session = await (
    await new SRPClientSession(new SRPRoutines()).step1("a", "b")
  ).step2(generateRandomBigInt(16), generateRandomBigInt(16));
  await t.rejects(() => session.step3(null!), /null/i);
  t.end();
});
