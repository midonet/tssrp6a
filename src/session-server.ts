import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";

export class SRPServerSession {
  constructor(private readonly routines: SRPRoutines) {}

  public step1(identifier: string, salt: bigint, verifier: bigint) {
    const b = this.routines.generatePrivateValue();
    const k = this.routines.computeK();
    const B = computeServerPublicValue(
      this.routines.parameters,
      k,
      verifier,
      b,
    );
    return new SRPServerSessionStep1(
      this.routines,
      identifier,
      salt,
      verifier,
      b,
      B,
    );
  }
}

class SRPServerSessionStep1 {
  constructor(
    public readonly routines: SRPRoutines,
    private readonly identifier: string,
    private readonly salt: bigint,
    private readonly verifier: bigint,
    private readonly b: bigint,
    public readonly B: bigint,
  ) {}

  /**
   * Compute the session key "S" without computing or checking client evidence
   */
  public sessionKey(A: bigint): bigint {
    if (A === null) {
      throw new Error("Client public value (A) must not be null");
    }

    if (!this.routines.isValidPublicValue(A)) {
      throw new Error(`Invalid Client public value (A): ${A.toString(16)}`);
    }

    const u = this.routines.computeU(A, this.B);
    const S = computeServerSessionKey(
      this.routines.parameters.N,
      this.verifier,
      u,
      A,
      this.b,
    );
    return S;
  }

  public step2(A: bigint, M1: bigint) {
    if (!M1) {
      throw new Error("Client evidence (M1) must not be null");
    }

    const S = this.sessionKey(A);

    const computedM1 = this.routines.computeClientEvidence(
      this.identifier,
      this.salt,
      A,
      this.B,
      S,
    );

    if (computedM1 !== M1) {
      throw new Error("Bad client credentials");
    }

    const M2 = this.routines.computeServerEvidence(A, M1, S);

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
