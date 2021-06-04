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

export type SRPClientSessionStep1State = {
  I: string;
  IH: Array<number>; // standard Array representation of the Uint8Array ArrayBuffer
};

export class SRPClientSessionStep1 {
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
    // TODO can we run any of these promises in parallel?
    const x = await this.routines.computeXStep2(salt, this.IH);
    const a = this.routines.generatePrivateValue();
    const A = this.routines.computeClientPublicValue(a);
    const k = await this.routines.computeK();
    const u = await this.routines.computeU(A, B);
    const S = this.routines.computeClientSessionKey(k, x, u, a, B);
    const M1 = await this.routines.computeClientEvidence(this.I, salt, A, B, S);

    return new SRPClientSessionStep2(this.routines, A, M1, S);
  }

  public toJSON(): SRPClientSessionStep1State {
    return { I: this.I, IH: Array.from(new Uint8Array(this.IH)) };
  }

  public static fromState(
    routines: SRPRoutines,
    state: SRPClientSessionStep1State,
  ) {
    return new SRPClientSessionStep1(
      routines,
      state.I,
      new Uint8Array(state.IH).buffer,
    );
  }
}

export type SRPClientSessionStep2State = {
  A: string; // hex representation of bigint
  M1: string;
  S: string;
};

export class SRPClientSessionStep2 {
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

  public toJSON(): SRPClientSessionStep2State {
    return {
      A: this.A.toString(16),
      M1: this.M1.toString(16),
      S: this.S.toString(16),
    };
  }

  public static fromState(
    routines: SRPRoutines,
    state: SRPClientSessionStep2State,
  ) {
    return new SRPClientSessionStep2(
      routines,
      BigInt("0x" + state.A),
      BigInt("0x" + state.M1),
      BigInt("0x" + state.S),
    );
  }
}
