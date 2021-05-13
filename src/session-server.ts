import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";

type SRPServerStateStep =
  | ISRPServerStateStepInit
  | ISRPServerStateStep1
  | ISRPServerStateStep2;
interface ISRPServerStateStepInit {
  step: "init";
}
interface ISRPServerStateStep1 {
  step: "1";
  identifier: string;
  salt: bigint;
  verifier: bigint;
  b: bigint;
  B: bigint;
}
interface ISRPServerStateStep2 {
  step: "2";
}

export class SRPServerSession {
  private routines: SRPRoutines;
  private state: SRPServerStateStep = { step: "init" };

  constructor(routines: SRPRoutines) {
    this.routines = routines;
  }

  public step1(identifier: string, salt: bigint, verifier: bigint) {
    if (this.state.step !== "init") {
      throw new Error("step1 not from init");
    }

    const b = this.routines.generatePrivateValue();
    const k = this.routines.computeK();
    const B = computeServerPublicValue(
      this.routines.parameters,
      k,
      verifier,
      b,
    );
    this.state = {
      step: "1",
      identifier,
      salt,
      verifier,
      b,
      B,
    };
    return B;
  }

  public step2(A: bigint, M1: bigint) {
    if (this.state.step !== "1") {
      throw new Error("step2 not from step1");
    }

    if (A === null) {
      throw new Error("Client public value (A) must not be null");
    }

    if (!this.routines.isValidPublicValue(A)) {
      throw new Error(`Invalid Client public value (A): ${A.toString(16)}`);
    }

    const { identifier, salt, verifier, b, B } = this.state;

    if (!M1) {
      throw new Error("Client evidence (M1) must not be null");
    }

    const u = this.routines.computeU(A, B);
    const S = computeServerSessionKey(
      this.routines.parameters.N,
      verifier,
      u,
      A,
      b,
    );

    const computedM1 = this.routines.computeClientEvidence(
      identifier,
      salt,
      A,
      B,
      S,
    );

    if (computedM1 !== M1) {
      throw new Error("Bad client credentials");
    }

    const M2 = this.routines.computeServerEvidence(A, M1, S);

    this.state = { step: "2" };
    return M2;
  }
}

const computeServerPublicValue = (
  parameters: SRPParameters,
  k: bigint,
  v: bigint,
  b: bigint,
): bigint => {
  return (modPow(parameters.g, b, parameters.N) + v * k) % parameters.N;
};

const computeServerSessionKey = (
  N: bigint,
  v: bigint,
  u: bigint,
  A: bigint,
  b: bigint,
): bigint => {
  return modPow(modPow(v, u, N) * A, b, N);
};
