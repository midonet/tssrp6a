/* eslint-disable no-fallthrough */
import { BigInteger } from "jsbn";
import { SRPConfig } from "../config";
import { SRPParameters } from "../parameters";
import { SRPRoutines } from "../routines";
import { SRPClientSession, SRPClientSessionState } from "../session-client";
import { generateRandomBigInteger, generateRandomString } from "../utils";
import { test } from "./tests";

const TestConfig = new SRPConfig(
  new SRPParameters(),
  (p) => new SRPRoutines(p),
);

class TestSRPClientSession extends SRPClientSession {
  constructor(startingState?: SRPClientSessionState, timeoutMillis?: number) {
    super(TestConfig, timeoutMillis);

    if (startingState) {
      this.stateStep = startingState;

      switch (this.stateStep) {
        case SRPClientSessionState.STEP_3:
        case SRPClientSessionState.STEP_2:
          this.assumeStep2();
        case SRPClientSessionState.STEP_1:
          this.assumeStep1();
        case SRPClientSessionState.INIT:
        default:
          break;
      }
    }
  }

  public assumeStep1(): void {
    this._registerActivity();
    this.I = generateRandomString(16);
    this.P = generateRandomString(16);
  }

  public assumeStep2(): void {
    this._registerActivity();
    this.A = generateRandomBigInteger();
    this.M1 = generateRandomBigInteger();
    this.S = generateRandomBigInteger();
  }
}

test("#SRPGetters success (set values)", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_3);

  t.doesNotThrow(() => session.I);
  t.doesNotThrow(() => session.P);
  t.doesNotThrow(() => session.A);
  t.doesNotThrow(() => session.M1);
  t.end();
});

test("#SRPGetters failure (not-set values)", (t) => {
  const session = new TestSRPClientSession();

  t.throws(() => session.I, /user identity.*not set/i);
  t.throws(() => session.P, /password.*not set/i);
  t.throws(() => session.A, /public client value.*not set/i);
  t.throws(() => session.M1, /client evidence.*not set/i);
  t.end();
});

test("#SRPSetters success (not set yet)", (t) => {
  const session = new TestSRPClientSession();

  const I = generateRandomString(16);
  const P = generateRandomString(16);
  const A = generateRandomBigInteger();
  const M1 = generateRandomBigInteger();

  t.doesNotThrow(() => {
    session.I = I;
  });
  t.doesNotThrow(() => {
    session.P = P;
  });
  t.doesNotThrow(() => {
    session.A = A;
  });
  t.doesNotThrow(() => {
    session.M1 = M1;
  });
  t.end();
});

test("#SRPSetters failure (already set)", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_3);

  const I = generateRandomString(16);
  const P = generateRandomString(16);
  const A = generateRandomBigInteger();
  const M1 = generateRandomBigInteger();

  t.throws(() => {
    session.I = I;
  }, /identity.*already set/i);
  t.throws(() => {
    session.P = P;
  }, /password.*already set/i);
  t.throws(() => {
    session.A = A;
  }, /public client val.*already set/i);
  t.throws(() => {
    session.M1 = M1;
  }, /evidence.*already set/i);
  t.end();
});

test("#SRPSetter failure (invalid)", (t) => {
  const session = new TestSRPClientSession();
  t.throws(() => {
    session.A = BigInteger.ZERO;
  }, /bad client public/i);
  t.end();
});

function stateErrorMatch(
  expected: SRPClientSessionState,
  found: SRPClientSessionState,
) {
  return new RegExp(`must be.*\\s${expected}\\s.*but is.*\\s${found}`);
}

test("#StateTransitionFromINIT step1 - success", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);

  t.doesNotThrow(() =>
    session.step1(generateRandomString(16), generateRandomString(16)),
  );
  t.end();
});
test("#StateTransitionFromINIT step2 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);

  t.throws(
    () => session.step2(BigInteger.ZERO, BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_1, SRPClientSessionState.INIT),
  );
  t.end();
});
test("#StateTransitionFromINIT step3 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);

  t.throws(
    () => session.step3(BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_2, SRPClientSessionState.INIT),
  );
  t.end();
});

test("#StateTransitionFrom1 step1 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);

  t.throws(
    () => session.step1("user", "password"),
    stateErrorMatch(SRPClientSessionState.INIT, SRPClientSessionState.STEP_1),
  );
  t.end();
});
test("#StateTransitionFrom1 step2 - success", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);

  t.doesNotThrow(() =>
    session.step2(generateRandomBigInteger(16), generateRandomBigInteger(16)),
  );
  t.end();
});
test("#StateTransitionFrom1 step3 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);

  t.throws(
    () => session.step3(BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_2, SRPClientSessionState.STEP_1),
  );
  t.end();
});

test("#StateTransitionFrom2 step1 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_2);

  t.throws(
    () => session.step1("user", "password"),
    stateErrorMatch(SRPClientSessionState.INIT, SRPClientSessionState.STEP_2),
  );
  t.end();
});
test("#StateTransitionFrom2 step2 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_2);

  t.throws(
    () => session.step2(BigInteger.ZERO, BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_1, SRPClientSessionState.STEP_2),
  );
  t.end();
});
test("#StateTransitionFrom2 step3 - success", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_2);

  t.throws(() => session.step3(generateRandomBigInteger(16)), /bad server/i);
  t.end();
});

test("#StateTransitionFrom3 step1 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_3);

  t.throws(
    () => session.step1("user", "password"),
    stateErrorMatch(SRPClientSessionState.INIT, SRPClientSessionState.STEP_3),
  );
  t.end();
});
test("#StateTransitionFrom3 step2 - failure", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_3);

  t.throws(
    () => session.step2(BigInteger.ZERO, BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_1, SRPClientSessionState.STEP_3),
  );
  t.end();
});
test("#StateTransitionFrom3 step3 - success", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_3);

  t.throws(
    () => session.step2(BigInteger.ZERO, BigInteger.ZERO),
    stateErrorMatch(SRPClientSessionState.STEP_1, SRPClientSessionState.STEP_3),
  );
  t.end();
});

test("#ParameterValidation1 All correct", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);
  t.doesNotThrow(() =>
    session.step1(generateRandomString(16), generateRandomString(16)),
  );
  t.end();
});

test("#ParameterValidation1 Null/Undefined Identity", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);
  t.throws(() => session.step1(null!, generateRandomString(16)), /null/i);
  t.end();
});

test("#ParameterValidation1 Empty Identity", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);
  t.throws(() => session.step1("", generateRandomString(16)), /empty/i);
  t.end();
});

test("#ParameterValidation1 Null/Undefined password", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.INIT);
  t.throws(() => session.step1(generateRandomString(16), null!), /null/i);
  t.end();
});

test("#ParameterValidation2 All correct", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);
  t.doesNotThrow(() =>
    session.step2(generateRandomBigInteger(16), generateRandomBigInteger(16)),
  );
  t.end();
});

test("#ParameterValidation2 Null/Undefined salt", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);
  t.throws(() => session.step2(null!, generateRandomBigInteger(16)), /null/i);
  t.end();
});

test("#ParameterValidation2 Null/Undefined B", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_1);
  t.throws(() => session.step2(generateRandomBigInteger(16), null!), /null/i);
  t.end();
});

test("#ParameterValidation3 All correct", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_2);
  // It throws because the fake values don't allow the verification to work
  t.throws(() => session.step3(generateRandomBigInteger(16)), /bad server/i);
  t.end();
});

test("#ParameterValidation3 Null/Undefined M2", (t) => {
  const session = new TestSRPClientSession(SRPClientSessionState.STEP_2);
  t.throws(() => session.step3(null!), /null/i);
  t.end();
});

const TIMEOUT_MILLIS = 100;

function doAfterTimeout(f: () => any): Promise<void> {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      try {
        f();
        resolve();
      } catch (e) {
        reject(e);
      }
    }, TIMEOUT_MILLIS + 50);
  });
}

test("#Timeout Step 2", (t) => {
  t.plan(1);
  const session = new TestSRPClientSession(
    SRPClientSessionState.STEP_1,
    TIMEOUT_MILLIS,
  );

  doAfterTimeout(() =>
    session.step2(generateRandomBigInteger(), generateRandomBigInteger()),
  ).catch((e) => {
    t.true(/timeout/i.test(e.message));
  });
});

test("#Timeout Step 3", (t) => {
  t.plan(1);
  const session = new TestSRPClientSession(
    SRPClientSessionState.STEP_2,
    TIMEOUT_MILLIS,
  );

  doAfterTimeout(() => session.step3(generateRandomBigInteger())).catch((e) => {
    t.true(/timeout/i.test(e.message));
  });
});

test("#Timeout password clear after step 2", (t) => {
  const session = new TestSRPClientSession();

  const I = generateRandomString(16);
  const P = generateRandomString(16);
  const s = generateRandomBigInteger(16);
  const B = generateRandomBigInteger(16);

  session.step1(I, P);

  t.equal(session.P, P);

  session.step2(s, B);

  t.throws(() => session.P, /not set/i);
  t.end();
});
