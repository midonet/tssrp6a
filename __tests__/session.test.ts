/* eslint-disable no-fallthrough */
import { BigInteger } from "jsbn";
import { test } from "../../../test/util";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import { SRPSession } from "../session";
import { SRPClientSession } from "../session-client";
import {
  bigIntegerToHex,
  createVerifier,
  evenLengthHex,
  generateRandomBigInteger,
  generateRandomHex,
  hash,
  hexToBigInteger,
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

const serverStep2 = (
  routines: SRPRoutines,
  N: BigInteger,
  B: BigInteger,
  s: string,
  v: string,
  b: BigInteger,
  I: string,
  AHex: string,
  M1Hex: string,
) => {
  if (!AHex) {
    throw new Error("Client public value (A) must not be null");
  }

  const A = hexToBigInteger(evenLengthHex(AHex));

  if (!routines.isValidPublicValue(A)) {
    throw new Error(`Invalid Client public value (A): ${AHex}`);
  }

  if (!M1Hex) {
    throw new Error("Client evidence (M1) must not be null");
  }

  const M1 = hexToBigInteger(evenLengthHex(M1Hex));

  const u = routines.computeU(A, B);
  const S = computeServerSessionKey(N, hexToBigInteger(v), u, A, b);

  const computedM1 = routines.computeClientEvidence(
    I,
    hexToBigInteger(s),
    A,
    B,
    S,
  );

  if (!computedM1.equals(M1)) {
    throw new Error("Bad client credentials");
  }

  const M2 = routines.computeServerEvidence(A, M1, S);

  return bigIntegerToHex(M2);
};

const computeServerPublicValue = (
  parameters: SRPParameters,
  k: BigInteger,
  v: BigInteger,
  b: BigInteger,
): BigInteger => {
  return parameters.g
    .modPow(b, parameters.N)
    .add(v.multiply(k))
    .mod(parameters.N);
};

const computeServerSessionKey = (
  N: BigInteger,
  v: BigInteger,
  u: BigInteger,
  A: BigInteger,
  b: BigInteger,
): BigInteger => {
  return v
    .modPow(u, N)
    .multiply(A)
    .modPow(b, N);
};

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
test.skip("#SRPSession success", (t) => {
  t.plan(2);
  const testUsername = generateRandomHex(16);
  const testPassword = generateRandomHex(16);

  const clientSession = new SRPClientSession(TestConfig);
  const routines = TestConfig.routines;

  const testSalt = routines.generateRandomSalt(16);

  const serverStorage = {
    s: testSalt,
    v: createVerifier(TestConfig, testUsername, testSalt, testPassword),
  };

  clientSession.step1(testUsername, testPassword);
  const b = routines.generatePrivateValue();
  const B = computeServerPublicValue(
    TestConfig.parameters,
    routines.computeK(),
    hexToBigInteger(serverStorage.s),
    b,
  );
  const clientCredentials = clientSession.step2(
    serverStorage.s,
    bigIntegerToHex(B),
  );

  t.doesNotThrow(() => {
    const M2 = serverStep2(
      routines,
      TestConfig.parameters.N,
      B,
      serverStorage.s,
      serverStorage.v,
      b,
      testUsername,
      clientCredentials.A,
      clientCredentials.M1,
    );
    clientSession.step3(M2);
  });

  t.end();
});

test("error - wrong password", (t) => {
  const testUsername = generateRandomHex(16);
  const testPassword = generateRandomHex(16);
  const diffPassword = `${testPassword}-diff`;

  const clientSession = new SRPClientSession(TestConfig);

  const testSalt = TestConfig.routines.generateRandomSalt(16);

  const serverStorage = {
    s: utf8ToHex(testSalt),
    v: createVerifier(TestConfig, testUsername, testSalt, testPassword),
  };

  clientSession.step1(testUsername, diffPassword);
  const B = computeServerPublicValue(
    TestConfig.parameters,
    TestConfig.routines.computeK(),
    hexToBigInteger(serverStorage.s),
    hexToBigInteger(serverStorage.v),
  );
  const clientCredentials = clientSession.step2(
    serverStorage.s,
    bigIntegerToHex(B),
  );
  t.throws(
    () =>
      serverStep2(
        TestConfig.routines,
        TestConfig.parameters.N,
        B,
        serverStorage.s,
        serverStorage.v,
        TestConfig.routines.generatePrivateValue(),
        testUsername,
        clientCredentials.A,
        clientCredentials.M1,
      ),
    /bad client credentials/i,
  );
  t.end();
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
