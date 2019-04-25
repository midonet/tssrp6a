/* eslint-disable no-fallthrough */
import { BigInteger } from "jsbn";
import { range } from "ramda";
import { test } from "../../../test/util";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import { SRPSession } from "../session";
import { SRPClientSession } from "../session-client";
import { SRPServerSession } from "../session-server";
import {
  bigIntegerToBase64,
  bigIntegerToWordArray,
  createVerifier,
  generateRandomBigInteger,
  generateRandomString,
  hash,
  wordArrayTobase64,
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

test('#SRPSession canary for password that is "uneven" as hex string', (t) => {
  t.plan(2);
  const testUsername = "peppapig";
  const testPassword = "edge00044bc49a26"; // problematic as reported by https://midobugs.atlassian.net/browse/ISS-325

  // salt is generated during signup, and sent to client.step2
  const salt = "Sxq7Zc++Cqb1DqUvTOmkxg==";

  // verifier is generated during signup, and read from storage to server.step1
  const verifier = createVerifier(TestConfig, testUsername, salt, testPassword);
  t.strictEqual(
    verifier,
    "jXLJ8zZRisLNvmpvZXwKrQGxEG5B/0JbuMy/+3Mp26pgk1bvcbMhkqKCYFVV4FU35jdIsKKIMeAZUaLBrIDUx+uz3ND/" +
      "lh6bOx3tOzJ2WJPqjh9jcSDVBRqyk8hTE/wYpZI6RIbuaHxYrjaFSc/jidYvg/fqHLLSLqrWdDRlthMly64Qu0Vada" +
      "p0eDbN1qCYyi4TtejACzJdKcGvTGfnsetZOSRnFb52rG5DCnGPEySRDn6Lu7cUVVFNVL+TJEsH3iN9KnoLV6lHUM7+" +
      "eWy3Qn1z0jfvkmmwR7de4ZZYk0r1sz04FoGk+wsJIoGakaHJR2mb5wnZYFEr57VkAXLA2g==",
  );

  const serverSession = new SRPServerSession(TestConfig);
  // server gets identifier from client, salt+verifier from db (from signup)
  const B = serverSession.step1(testUsername, salt, verifier);

  const clientSession = new SRPClientSession(TestConfig);
  clientSession.step1(testUsername, testPassword);
  const { A, M1 } = clientSession.step2(salt, B);

  const M2 = serverSession.step2(A, M1);
  clientSession.step3(M2);
  t.pass("Canary test passes");
});

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
  const TEST_COUNT = 20;
  t.plan(TEST_COUNT);
  range(0, TEST_COUNT).forEach((i) => {
    const testUsername = generateRandomString(10);
    const testPassword = generateRandomString(15);

    // salt is generated during signup, and sent to client.step2
    const salt = TestConfig.routines.generateRandomSalt(16);

    // verifier is generated during signup, and read from storage to server.step1
    const verifier = createVerifier(
      TestConfig,
      testUsername,
      salt,
      testPassword,
    );

    const serverSession = new SRPServerSession(TestConfig);
    // server gets identifier from client, salt+verifier from db (from signup)
    const B = serverSession.step1(testUsername, salt, verifier);

    const clientSession = new SRPClientSession(TestConfig);
    clientSession.step1(testUsername, testPassword);
    const { A, M1 } = clientSession.step2(salt, B);

    const M2 = serverSession.step2(A, M1);
    clientSession.step3(M2);
    t.pass(
      `Random test #${i} user:${testUsername}, password:${testPassword}, salt: ${salt}`,
    );
  });
});

test("error - wrong password", (t) => {
  t.plan(1);
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);
  const diffPassword = `${testPassword}-diff`;

  const routines = TestConfig.routines;

  const salt = routines.generateRandomSalt(16);

  const verifier = createVerifier(TestConfig, testUsername, salt, testPassword);

  const serverSession = new SRPServerSession(TestConfig);
  const B = serverSession.step1(testUsername, salt, verifier);

  const clientSession = new SRPClientSession(TestConfig);
  clientSession.step1(testUsername, diffPassword);
  const { A, M1 } = clientSession.step2(salt, B);

  t.throws(() => {
    serverSession.step2(A, M1);
  }, /bad client credentials/i);
});

test("error - not in step 1", (t) => {
  t.plan(1);

  const serverSession = new SRPServerSession(TestConfig);

  t.throws(() => {
    serverSession.step2(
      bigIntegerToBase64(BigInteger.ONE),
      bigIntegerToBase64(BigInteger.ONE),
    );
  }, /step2 not from step1/i);
});

test('error - not in step "init"', (t) => {
  t.plan(1);
  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  const routines = TestConfig.routines;

  const salt = routines.generateRandomSalt(16);

  const verifier = createVerifier(TestConfig, testUsername, salt, testPassword);

  const serverSession = new SRPServerSession(TestConfig);
  serverSession.step1(testUsername, salt, verifier);

  t.throws(() => {
    serverSession.step1(testUsername, salt, verifier);
  }, /step1 not from init/i);
});

test("error - bad/empty A or M1", (t) => {
  t.plan(5);

  const someBase64 = "YmFzZTY0";

  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", someBase64, someBase64);
    serverSession.step2("", bigIntegerToBase64(BigInteger.ONE));
  }, /Client public value \(A\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", someBase64, someBase64);
    serverSession.step2(null as any, bigIntegerToBase64(BigInteger.ONE));
  }, /Client public value \(A\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", someBase64, someBase64);
    serverSession.step2(someBase64, "");
  }, /Client evidence \(M1\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", someBase64, someBase64);
    serverSession.step2(someBase64, null as any);
  }, /Client evidence \(M1\) must not be null/i);
  t.throws(() => {
    const serverSession = new SRPServerSession(TestConfig);
    serverSession.step1("pepi", someBase64, someBase64);
    const badA = bigIntegerToBase64(BigInteger.ZERO);
    serverSession.step2(badA, someBase64);
  }, /Invalid Client public value \(A\): /i);
});

test("#SRPSessionGetters success (set values)", (t) => {
  const session = new TestSRPSession();

  session.S = generateRandomBigInteger();

  t.doesNotThrow(() => session.S);
  t.equals(session.sharedKey, session.S);
  t.equals(
    session.hashedSharedKey,
    wordArrayTobase64(
      hash(session.config.parameters, bigIntegerToWordArray(session.S)),
    ),
  );
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
