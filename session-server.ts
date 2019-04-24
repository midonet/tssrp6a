import { BigInteger } from "jsbn";
import { bigIntegerToHex, SRPConfig, SRPParameters } from ".";
import { evenLengthHex, hexToBigInteger } from "./utils";

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
  salt: string;
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

  public step1(identifier: string, salt: string, verifierHex: string) {
    if (this.state.step !== "init") {
      throw new Error("step1 not from init");
    }

    const b = this.config.routines.generatePrivateValue();
    const k = this.config.routines.computeK();
    const verifier = hexToBigInteger(verifierHex);
    const B = computeServerPublicValue(this.config.parameters, k, verifier, b);
    this.state = { step: "1", identifier, salt, verifier, b, B };
    return B;
  }

  public step2(AHex: string, M1Hex: string) {
    if (this.state.step !== "1") {
      throw new Error("step2 not from step1");
    }

    if (!AHex) {
      throw new Error("Client public value (A) must not be null");
    }

    const A = hexToBigInteger(evenLengthHex(AHex));

    if (!this.config.routines.isValidPublicValue(A)) {
      throw new Error(`Invalid Client public value (A): ${AHex}`);
    }

    const { identifier, salt, verifier, b, B } = this.state;

    if (!M1Hex) {
      throw new Error("Client evidence (M1) must not be null");
    }

    const M1 = hexToBigInteger(evenLengthHex(M1Hex));

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
      hexToBigInteger(salt),
      A,
      B,
      S,
    );

    if (!computedM1.equals(M1)) {
      throw new Error("Bad client credentials");
    }

    const M2 = this.config.routines.computeServerEvidence(A, M1, S);

    this.state = { step: "2" };
    return bigIntegerToHex(M2);
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
  return v
    .modPow(u, N)
    .multiply(A)
    .modPow(b, N);
};
