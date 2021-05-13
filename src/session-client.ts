import { SRPRoutines } from "./routines";
import { HashWordArray } from "./utils";

export class SRPClientSession {
  constructor(private readonly routines: SRPRoutines) {}
  public step1(userId: string, userPassword: string): SRPClientSessionStep1 {
    if (!userId || !userId.trim()) {
      throw new Error("User identity must not be null nor empty");
    }
    if (!userPassword) {
      throw new Error("User password must not be null");
    }

    const IH = this.routines.computeIdentityHash(userId, userPassword);
    return new SRPClientSessionStep1(this.routines, userId, IH);
  }
}

class SRPClientSessionStep1 {
  constructor(
    private readonly routines: SRPRoutines,
    private readonly I: string,
    public readonly IH: HashWordArray,
  ) {}
  public step2(salt: bigint, B: bigint): SRPClientSessionStep2 {
    if (!salt) {
      throw new Error("Salt (s) must not be null");
    }

    if (!B) {
      throw new Error("Public server value (B) must not be null");
    }

    const x = this.routines.computeXStep2(salt, this.IH);
    const a = this.routines.generatePrivateValue();
    const A = this.routines.computeClientPublicValue(a);
    const k = this.routines.computeK();
    const u = this.routines.computeU(A, B);
    const S = this.routines.computeClientSessionKey(k, x, u, a, B);
    const M1 = this.routines.computeClientEvidence(this.I, salt, A, B, S);

    return new SRPClientSessionStep2(this.routines, A, M1, S);
  }
}

class SRPClientSessionStep2 {
  constructor(
    private readonly routines: SRPRoutines,
    public readonly A: bigint,
    public readonly M1: bigint,
    public readonly S: bigint,
  ) {}
  public step3(M2: bigint): void {
    if (!M2) {
      throw new Error("Server evidence (M2) must not be null");
    }

    const computedM2 = this.routines.computeServerEvidence(
      this.A,
      this.M1,
      this.S,
    );

    if (computedM2 !== M2) {
      throw new Error("Bad server credentials");
    }
  }
}
