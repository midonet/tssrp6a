import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";
import { modPow } from "./utils";

// Variable names match the RFC (I, IH, S, b, B, salt, b, A, M1, M2...)

export class SRPServerSession {
  constructor(private readonly routines: SRPRoutines) {}

  public async step1(
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
    const k = await this.routines.computeK();
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

type SRPServerSessionStep1State = {
  identifier: string;
  salt: string; // hex representation of bigint
  verifier: string;
  b: string;
  B: string;
};

export class SRPServerSessionStep1 {
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
  public async sessionKey(
    /**
     * Client public key "A"
     */
    A: bigint,
  ): Promise<bigint> {
    if (A === null) {
      throw new Error("Client public value (A) must not be null");
    }

    if (!this.routines.isValidPublicValue(A)) {
      throw new Error(`Invalid Client public value (A): ${A.toString(16)}`);
    }

    const u = await this.routines.computeU(A, this.B);
    const S = computeServerSessionKey(
      this.routines.parameters.primeGroup.N,
      this.verifier,
      u,
      A,
      this.b,
    );
    return S;
  }

  public async step2(
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

    const S = await this.sessionKey(A);

    const computedM1 = await this.routines.computeClientEvidence(
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

  public toJSON(): SRPServerSessionStep1State {
    return {
      identifier: this.identifier,
      salt: this.salt.toString(16),
      verifier: this.verifier.toString(16),
      b: this.b.toString(16),
      B: this.B.toString(16),
    };
  }

  public static fromState(
    routines: SRPRoutines,
    state: SRPServerSessionStep1State,
  ) {
    return new SRPServerSessionStep1(
      routines,
      state.identifier,
      BigInt("0x" + state.salt),
      BigInt("0x" + state.verifier),
      BigInt("0x" + state.b),
      BigInt("0x" + state.B),
    );
  }
}

const computeServerPublicValue = (
  parameters: SRPParameters,
  k: bigint,
  v: bigint,
  b: bigint,
): bigint => {
  return (
    (modPow(parameters.primeGroup.g, b, parameters.primeGroup.N) + v * k) %
    parameters.primeGroup.N
  );
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
