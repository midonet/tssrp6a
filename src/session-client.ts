import { SRPRoutines } from "./routines";

// Variable names match the RFC (I, IH, S, b, B, salt, b, A, M1, M2...)

export class SRPClientSession {
  constructor(private readonly routines: SRPRoutines) {}
  public async step1(
    /**
     * User identity
     */
    userId: string,
    /**
     * User password (not kept in state)
     */
    userPassword: string,
  ): Promise<SRPClientSessionStep1> {
    if (!userId || !userId.trim()) {
      throw new Error("User identity must not be null nor empty");
    }
    if (!userPassword) {
      throw new Error("User password must not be null");
    }

    const IH = await this.routines.computeIdentityHash(userId, userPassword);
    return new SRPClientSessionStep1(this.routines, userId, IH);
  }
}

class SRPClientSessionStep1 {
  constructor(
    private readonly routines: SRPRoutines,
    /**
     * User identity
     */
    private readonly I: string,
    /**
     * User identity/password hash
     */
    public readonly IH: ArrayBuffer,
  ) {}

  public async step2(
    /**
     * Some generated salt (see createVerifierAndSalt)
     */
    salt: bigint,
    /**
     * Server public key "B"
     */
    B: bigint,
  ): Promise<SRPClientSessionStep2> {
    if (!salt) {
      throw new Error("Salt (s) must not be null");
    }

    if (!B) {
      throw new Error("Public server value (B) must not be null");
    }
    // TODO can we run any of these promises at the same time?
    const x = await this.routines.computeXStep2(salt, this.IH);
    const a = this.routines.generatePrivateValue();
    const A = this.routines.computeClientPublicValue(a);
    const k = await this.routines.computeK();
    const u = await this.routines.computeU(A, B);
    const S = this.routines.computeClientSessionKey(k, x, u, a, B);
    const M1 = await this.routines.computeClientEvidence(this.I, salt, A, B, S);

    return new SRPClientSessionStep2(this.routines, A, M1, S);
  }
}

class SRPClientSessionStep2 {
  constructor(
    private readonly routines: SRPRoutines,
    /**
     * Client public value "A"
     */
    public readonly A: bigint,
    /**
     * Client evidence message "M1"
     */
    public readonly M1: bigint,
    /**
     * Shared session key "S"
     */
    public readonly S: bigint,
  ) {}

  public async step3(M2: bigint): Promise<void> {
    if (!M2) {
      throw new Error("Server evidence (M2) must not be null");
    }

    const computedM2 = await this.routines.computeServerEvidence(
      this.A,
      this.M1,
      this.S,
    );

    if (computedM2 !== M2) {
      throw new Error("Bad server credentials");
    }
  }
}
