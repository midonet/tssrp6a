/* eslint-disable no-fallthrough */
import { BigInteger } from "jsbn";
import { test } from "../../../test/util";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import { SRPSession } from "../session";
import { SRPClientSession } from "../session-client";
import { SRPServerSession } from "../session-server";
import {
  bigIntegerToHex,
  createVerifier,
  generateRandomBigInteger,
  generateRandomHex,
  hash,
  utf8ToHex,
} from "../utils";

const TestConfig = new SRPConfig(
  new SRPParameters(),
  (p) => new SRPRoutines(p),
);

class TestSRPSession extends SRPSession {
  constructor(timeoutMillis?: number) {
    super(TestConfig, timeoutMillis);
  }
}

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
test("#SRPSession success", (t) => {
  t.plan(1);
  const testUsername = generateRandomHex(16);
  const testPassword = generateRandomHex(16);

  const routines = TestConfig.routines;

  // salt is generated during signup, and sent to client.step2
  const salt = routines.generateRandomSalt(16);
  const saltHex = utf8ToHex(salt);

  // verifier is generated during signup, and read from storage to server.step1
  const verifierHex = createVerifier(
    TestConfig,
    testUsername,
    salt,
    testPassword,
  );

  const serverSession = new SRPServerSession(TestConfig);
  // server gets identifier from client, salt+verifier from db (from signup)
  const B = serverSession.step1(testUsername, saltHex, verifierHex);

  const clientSession = new SRPClientSession(TestConfig);
  clientSession.step1(testUsername, testPassword);
  const { A, M1 } = clientSession.step2(saltHex, bigIntegerToHex(B));

  const M2 = serverSession.step2(A, M1);
  clientSession.step3(M2);
  t.ok("finished step 3");
});

test("error - wrong password", (t) => {
  t.plan(1);
  const testUsername = generateRandomHex(16);
  const testPassword = generateRandomHex(16);
  const diffPassword = `${testPassword}-diff`;

  const routines = TestConfig.routines;

  const salt = routines.generateRandomSalt(16);
  const saltHex = utf8ToHex(salt);

  const verifierHex = createVerifier(
    TestConfig,
    testUsername,
    salt,
    testPassword,
  );

  const serverSession = new SRPServerSession(TestConfig);
  const B = serverSession.step1(testUsername, saltHex, verifierHex);

  const clientSession = new SRPClientSession(TestConfig);
  clientSession.step1(testUsername, diffPassword);
  const { A, M1 } = clientSession.step2(saltHex, bigIntegerToHex(B));

  t.throws(() => {
    serverSession.step2(A, M1);
  }, /bad client credentials/i);
});

test("error - not in step 1", (t) => {
  t.plan(1);

  const serverSession = new SRPServerSession(TestConfig);

  t.throws(() => {
    serverSession.step2(
      bigIntegerToHex(BigInteger.ONE),
      bigIntegerToHex(BigInteger.ONE),
    );
  }, /step2 not from step1/i);
});

test("error - bad/empty A or M1", (t) => {
  t.plan(5);

  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", "01", "02");
    serverSession.step2("", bigIntegerToHex(BigInteger.ONE));
  }, /Client public value \(A\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", "01", "02");
    serverSession.step2(null as any, bigIntegerToHex(BigInteger.ONE));
  }, /Client public value \(A\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", "01", "02");
    serverSession.step2(bigIntegerToHex(BigInteger.ONE), "");
  }, /Client evidence \(M1\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", "01", "02");
    serverSession.step2(bigIntegerToHex(BigInteger.ONE), null as any);
  }, /Client evidence \(M1\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", "01", "02");
    const badA = bigIntegerToHex(BigInteger.ZERO);
    serverSession.step2(badA, bigIntegerToHex(BigInteger.ONE));
  }, /Invalid Client public value \(A\): /i);
});

test("#SRPSessionGetters success (set values)", (t) => {
  const session = new TestSRPSession();

  session.S = generateRandomBigInteger();

  t.doesNotThrow(() => session.S);
  t.equals(session.sharedKey, session.S);
  t.equals(session.hashedSharedKey, hash(session.config.parameters, session.S));
  t.end();
});

test("#SRPSessionGetters failure (not-set values)", (t) => {
  const session = new TestSRPSession();

  t.throws(() => session.S, /shared key.*not set/i);
  t.end();
});

test("#SRPSessionSetters success (not set yet)", (t) => {
  const session = new TestSRPSession();

  const S = generateRandomBigInteger();

  t.doesNotThrow(() => {
    session.S = S;
  });
  t.end();
});

test("#SRPSessionSetters failure (already set)", (t) => {
  const session = new TestSRPSession();

  const S = generateRandomBigInteger();

  session.S = S;

  t.throws(() => {
    session.S = S;
  }, /shared key.*already set/i);
  t.end();
});
