import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import {
  SRPClientSession,
  SRPClientSessionStep1,
  SRPClientSessionStep2,
} from "../src/session-client";
import { SRPServerSession, SRPServerSessionStep1 } from "../src/session-server";
import { createVerifierAndSalt, generateRandomString } from "../src/utils";
import { serialize, deserialize } from "../src/serde";
import { test } from "./tests";

const TEST_ROUTINES = new SRPRoutines(new SRPParameters());

test("#Server serde", async (t) => {
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    TEST_ROUTINES,
    testUsername,
    testPassword,
  );

  // serialized server step1, and B
  // B is sent back to client, server_str is stored into some kind of webserver
  // session for this user
  const [server_str, B] = await (async (): Promise<[string, bigint]> => {
    const server = await new SRPServerSession(TEST_ROUTINES).step1(
      testUsername,
      salt,
      verifier,
    );
    const B = server.B;

    return [serialize(server), B];
  })();

  const client = await new SRPClientSession(TEST_ROUTINES).step1(
    testUsername,
    testPassword,
  );

  const client_step2 = await client.step2(salt, B);

  // assume that server_str was stored/loaded from some session
  const server_step1 = deserialize(server_str, SRPServerSessionStep1.prototype);
  const M2 = await server_step1.step2(client_step2.A, client_step2.M1);

  await client_step2.step3(M2);
  t.pass("all steps passed");
});

test("#Client serde", async (t) => {
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    TEST_ROUTINES,
    testUsername,
    testPassword,
  );

  const client_step1_str = await (async (): Promise<string> => {
    const client = await new SRPClientSession(TEST_ROUTINES).step1(
      testUsername,
      testPassword,
    );
    return serialize(client);
  })();

  const server = await new SRPServerSession(TEST_ROUTINES).step1(
    testUsername,
    salt,
    verifier,
  );

  const client = deserialize(client_step1_str, SRPClientSessionStep1.prototype);
  const [client_step2_str, A, M1] = await (async (): Promise<
    [string, bigint, bigint]
  > => {
    const client_step2 = await client.step2(salt, server.B);
    return [serialize(client_step2), client_step2.A, client_step2.M1];
  })();

  const M2 = await server.step2(A, M1);

  await deserialize(client_step2_str, SRPClientSessionStep2.prototype).step3(
    M2,
  );
  t.pass("all steps passed");
});

test("#serde with unknown hash function throws", async (t) => {
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  const { s: salt, v: verifier } = await createVerifierAndSalt(
    TEST_ROUTINES,
    testUsername,
    testPassword,
  );

  const params = new SRPParameters(SRPParameters.PrimeGroup[2048], (data) =>
    Promise.resolve(data),
  );
  const server = await new SRPServerSession(new SRPRoutines(params)).step1(
    testUsername,
    salt,
    verifier,
  );

  t.throws(() => {
    serialize(server);
  });
});
