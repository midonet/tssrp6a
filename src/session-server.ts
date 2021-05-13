import { BigInteger } from "jsbn";
import { SRPConfig } from "./config";
import { SRPParameters } from "./parameters";

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
  salt: BigInteger;
  verifier: BigInteger;
  b: BigInteger;
  B: BigInteger;
}
interface ISRPServerStateStep2 {
  step: "2";
}

export class SRPServerSession {
  private config: SRPConfig;
  private state: SRPServerStateStep = { step: "init" };
  constructor(config: SRPConfig) {
    this.config = config;
  }

  public step1(identifier: string, salt: BigInteger, verifier: BigInteger) {
    if (this.state.step !== "init") {
      throw new Error("step1 not from init");
    }

    const b = this.config.routines.generatePrivateValue();
    const k = this.config.routines.computeK();
    const B = computeServerPublicValue(this.config.parameters, k, verifier, b);
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

  public step2(A: BigInteger, M1: BigInteger) {
    if (this.state.step !== "1") {
      throw new Error("step2 not from step1");
    }

    if (!A) {
      throw new Error("Client public value (A) must not be null");
    }

    if (!this.config.routines.isValidPublicValue(A)) {
      throw new Error(`Invalid Client public value (A): ${A.toString(16)}`);
    }

    const { identifier, salt, verifier, b, B } = this.state;

    if (!M1) {
      throw new Error("Client evidence (M1) must not be null");
    }

    const u = this.config.routines.computeU(A, B);
    const S = computeServerSessionKey(
      this.config.parameters.N,
      verifier,
      u,
      A,
      b,
    );

    const computedM1 = this.config.routines.computeClientEvidence(
      identifier,
      salt,
      A,
      B,
      S,
    );

    if (!computedM1.equals(M1)) {
      throw new Error("Bad client credentials");
    }

    const M2 = this.config.routines.computeServerEvidence(A, M1, S);

    this.state = { step: "2" };
    return M2;
  }
}

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
  return v.modPow(u, N).multiply(A).modPow(b, N);
};
