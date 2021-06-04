import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import {
  SRPClientSession,
  SRPClientSessionStep1,
  SRPClientSessionStep2,
} from "../src/session-client";
import { SRPServerSession, SRPServerSessionStep1 } from "../src/session-server";
import { createVerifierAndSalt, generateRandomString } from "../src/utils";
import { test } from "./tests";

const TEST_ROUTINES = new SRPRoutines(new SRPParameters());

test("#SRP serialization", async (t) => {
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    TEST_ROUTINES,
    testUsername,
    testPassword,
  );

  const serverStep1 = await new SRPServerSession(TEST_ROUTINES).step1(
    testUsername,
    salt,
    verifier,
  );

  const serializedServerStep1 = JSON.stringify(serverStep1); // internally calls .toJSON

  // call fromState to deserialize and resume state
  const deserializedServerStep1 = SRPServerSessionStep1.fromState(
    TEST_ROUTINES,
    JSON.parse(serializedServerStep1),
  );

  const clientStep1 = await new SRPClientSession(TEST_ROUTINES).step1(
    testUsername,
    testPassword,
  );

  const serializedClientStep1 = JSON.stringify(clientStep1);

  const deserializedClientStep1 = SRPClientSessionStep1.fromState(
    TEST_ROUTINES,
    JSON.parse(serializedClientStep1),
  );

  const clientStep2 = await deserializedClientStep1.step2(
    salt,
    deserializedServerStep1.B,
  );

  const serializedClientStep2 = JSON.stringify(clientStep2);

  const deserializedClientStep2 = SRPClientSessionStep2.fromState(
    TEST_ROUTINES,
    JSON.parse(serializedClientStep2),
  );

  const M2 = await deserializedServerStep1.step2(
    deserializedClientStep2.A,
    deserializedClientStep2.M1,
  );
  await deserializedClientStep2.step3(M2);

  t.pass(
    `Serialization user:${testUsername}, password:${testPassword}, salt: ${salt}`,
  );
});
