import { modPow } from "bigint-mod-arith";
import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";

// Variable names match the RFC (I, IH, S, b, B, salt, b, A, M1, M2...)

export class SRPServerSession {
  constructor(private readonly routines: SRPRoutines) {}

  public step1(
    /**
     * User identity
     */
    identifier: string,
    /**
     * User salt
     */
    salt: bigint,
    /**
     * User verifier
     */
    verifier: bigint,
  ) {
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
    /**
     * User identity
     */
    private readonly identifier: string,
    /**
     * User salt
     */
    private readonly salt: bigint,
    /**
     * User verifier
     */
    private readonly verifier: bigint,
    /**
     * Server private key "b"
     */
    private readonly b: bigint,
    /**
     * Serve public key "B"
     */
    public readonly B: bigint,
  ) {}

  /**
   * Compute the session key "S" without computing or checking client evidence
   */
  public sessionKey(
    /**
     * Client public key "A"
     */
    A: bigint,
  ): bigint {
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

  public step2(
    /**
     * Client public key "A"
     */
    A: bigint,
    /**
     * Client message "M1"
     */
    M1: bigint,
  ) {
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
