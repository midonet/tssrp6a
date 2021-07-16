import bigInt from "big-integer";
import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { SRPServerSession } from "../src/session-server";
import {
  createVerifier,
  createVerifierAndSalt,
  generateRandomBigInt,
  generateRandomString,
} from "../src/utils";
import { test } from "./tests";

const ZERO = bigInt("0");
const ONE = bigInt("1");

const TEST_ROUTINES = new SRPRoutines(new SRPParameters());

/**
 * Preconditions:
 * * Server has 'v' and 's' in storage associated with 'I'
 * Step 1:
 * * User --(I, P)--> Client
 * * Client --(I)--> Server
 * * Server calculates 'B' and retrieves 's'
 * * Client <--(B, s)-- Server
 * Step 2:
 * * Client calculates 'A' and 'M1'
 * * Client --(A, M1)--> Server
 * * Server validates client using 'A' and 'M1' and calculates 'M2'
 * * Client <--(M2)-- Server
 * Step 3:
 * * Client validates server using 'M2'
 */
test("#SRP6a_Nimbusds_Session success", async (t) => {
  const TEST_COUNT = 20;
  t.plan(TEST_COUNT);
  for (const i of Array(TEST_COUNT).keys()) {
    const testUsername = generateRandomString(10);
    const testPassword = generateRandomString(15);

    // salt and verifier are generated by client during signup
    // verifier is read from server storage for server.step1
    const { s: salt, v: verifier } = await createVerifierAndSalt(
      TEST_ROUTINES,
      testUsername,
      testPassword,
    );

    // server gets identifier from client, salt+verifier from db (from signup)
    const server = await new SRPServerSession(TEST_ROUTINES).step1(
      testUsername,
      salt,
      verifier,
    );

    const client = await new SRPClientSession(TEST_ROUTINES).step1(
      testUsername,
      testPassword,
    );
    const client_step2 = await client.step2(salt, server.B);

    const M2 = await server.step2(client_step2.A, client_step2.M1);
    await client_step2.step3(M2);
    t.pass(
      `Random test #${i} user:${testUsername}, password:${testPassword}, salt: ${salt}`,
    );
  }
});

test("error - wrong password", async (t) => {
  t.plan(1);
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);
  const diffPassword = `${testPassword}-diff`;

  const salt = await TEST_ROUTINES.generateRandomSalt(16);

  const verifier = await createVerifier(
    TEST_ROUTINES,
    testUsername,
    salt,
    testPassword,
  );

  const server = await new SRPServerSession(TEST_ROUTINES).step1(
    testUsername,
    salt,
    verifier,
  );

  const clientSession = await new SRPClientSession(TEST_ROUTINES).step1(
    testUsername,
    diffPassword,
  );
  const { A, M1 } = await clientSession.step2(salt, server.B);

  await t.rejects(() => server.step2(A, M1), /bad client credentials/i);
});

test("error - bad/empty A or M1", async (t) => {
  t.plan(5);

  const someBigInteger = generateRandomBigInt();

  await t.rejects(async () => {
    const serverSession = new SRPServerSession(TEST_ROUTINES);
    return await (
      await serverSession.step1("pepi", someBigInteger, someBigInteger)
    ).step2(null!, ONE);
  }, /Client public value \(A\) must not be null/i);
  await t.rejects(async () => {
    const serverSession = new SRPServerSession(TEST_ROUTINES);
    return await (
      await serverSession.step1("pepi", someBigInteger, someBigInteger)
    ).step2(null as any, someBigInteger);
  }, /Client public value \(A\) must not be null/i);
  await t.rejects(async () => {
    const serverSession = new SRPServerSession(TEST_ROUTINES);
    return await (
      await serverSession.step1("pepi", someBigInteger, someBigInteger)
    ).step2(someBigInteger, null!);
  }, /Client evidence \(M1\) must not be null/i);
  await t.rejects(async () => {
    const serverSession = new SRPServerSession(TEST_ROUTINES);
    return await (
      await serverSession.step1("pepi", someBigInteger, someBigInteger)
    ).step2(someBigInteger, null as any);
  }, /Client evidence \(M1\) must not be null/i);
  await t.rejects(async () => {
    const serverSession = new SRPServerSession(TEST_ROUTINES);
    return await (
      await serverSession.step1("pepi", someBigInteger, someBigInteger)
    ).step2(ZERO, someBigInteger);
  }, /Invalid Client public value \(A\): /i);
});
