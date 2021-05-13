import { SRPRoutines } from "./routines";
import { HashWordArray } from "./utils";

export enum SRPClientSessionState {
  INIT = "INIT",
  STEP_1 = "STEP_1",
  STEP_2 = "STEP_2",
  STEP_3 = "STEP_3",
}

export interface ISRPClientCredentials {
  A: bigint;
  M1: bigint;
}

export class SRPClientSession {
  /**
   * SRPRoutines with SRPParameters used in this session.
   */
  private _routines: SRPRoutines;

  /**
   * Shared session key "S"
   */
  private _S?: bigint;

  /**
   * User identity
   */
  private _I?: string;

  /**
   * User identity hash
   */
  private _IH?: HashWordArray;

  /**
   * Client public value "A"
   */
  private _A?: bigint;

  /**
   * Client evidence message "M1"
   */
  private _M1?: bigint;

  /**
   * Number of milliseconds between session activity before timing out this
   * session.
   */
  private _timeoutMillis?: number;

  /**
   * Id of timer used for expiration timeout.
   */
  private _timeoutId: any;

  /**
   * Boolean determining if this session has timed out.
   */
  private _timedOut: boolean;

  /**
   * Current client auth state
   */
  protected stateStep: SRPClientSessionState;

  constructor(routines: SRPRoutines, timeoutMillis?: number) {
    this._routines = routines;
    this._timeoutMillis = timeoutMillis;
    this._timedOut = false;
    this.stateStep = SRPClientSessionState.INIT;
  }

  public step1(userId: string, userPassword: string): void {
    this._expectState(SRPClientSessionState.INIT);

    if (!userId || !userId.trim()) {
      throw new Error("User identity must not be null nor empty");
    }
    if (!userPassword) {
      throw new Error("User password must not be null");
    }

    this.I = userId;
    this.identityHash = this.routines.computeIdentityHash(userId, userPassword);
    this.stateStep = SRPClientSessionState.STEP_1;
    this._registerActivity();
  }

  public step2(salt: bigint, B: bigint): ISRPClientCredentials {
    this._expectState(SRPClientSessionState.STEP_1);
    this._throwOnTimeout();

    if (!salt) {
      throw new Error("Salt (s) must not be null");
    }

    if (!B) {
      throw new Error("Public server value (B) must not be null");
    }

    const x = this.routines.computeXStep2(salt, this.identityHash);
    const a = this.routines.generatePrivateValue();
    this.A = this.routines.computeClientPublicValue(a);
    const k = this.routines.computeK();
    const u = this.routines.computeU(this.A, B);
    this.S = this.routines.computeClientSessionKey(k, x, u, a, B);
    this.M1 = this.routines.computeClientEvidence(
      this.I,
      salt,
      this.A,
      B,
      this.S,
    );

    this.stateStep = SRPClientSessionState.STEP_2;
    this._registerActivity();

    return {
      A: this.A,
      M1: this.M1,
    };
  }

  public step3(M2: bigint): void {
    this._expectState(SRPClientSessionState.STEP_2);
    this._throwOnTimeout();

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

    this.stateStep = SRPClientSessionState.STEP_3;
    this._registerActivity();
  }

  get state(): SRPClientSessionState {
    return this.stateStep;
  }

  get S(): bigint {
    if (this._S) {
      return this._S;
    }

    throw new Error("Shared Key (S) not set");
  }

  set S(S: bigint) {
    if (this._S) {
      throw new Error(`Shared key (S) already set: ${this._S.toString(16)}`);
    }

    this._S = S;
  }

  get hashedSharedKey(): bigint {
    return this.routines.hashAsBigInt(this.S);
  }

  get routines(): SRPRoutines {
    return this._routines;
  }

  protected _throwOnTimeout() {
    if (this._timedOut) {
      throw new Error("Session timeout");
    }
  }

  protected _registerActivity(): void {
    if (this._timeoutMillis && !this._timedOut) {
      if (this._timeoutId) {
        clearTimeout(this._timeoutId);
      }

      this._timeoutId = setTimeout(() => {
        this._timedOut = true;
      }, this._timeoutMillis);
    }
  }
  get I(): string {
    if (this._I) {
      return this._I;
    }

    throw new Error("User Identity (I) not set");
  }

  set I(I: string) {
    if (this._I) {
      throw new Error(`User identity (I) already set: ${this._I}`);
    }

    this._I = I;
  }

  get identityHash(): HashWordArray {
    if (this._IH) {
      return this._IH;
    }

    throw new Error("Identity hash is not set");
  }

  set identityHash(identityHash: HashWordArray) {
    if (identityHash.sigBytes << 3 !== this.routines.parameters.HBits) {
      throw new Error(
        `Hash array must have correct size in bits: ${this.routines.parameters.HBits}`,
      );
    }
    if (this._IH) {
      throw new Error(`User identity hash (_IH) already set: ${this._IH}`);
    }

    this._IH = identityHash;
  }

  get A(): bigint {
    if (this._A) {
      return this._A;
    }

    throw new Error("Public client value (A) not set");
  }

  set A(A: bigint) {
    if (this._A) {
      throw new Error(
        `Public client value (A) already set: ${this._A.toString(16)}`,
      );
    }

    if (!this.routines.isValidPublicValue(A)) {
      throw new Error(`Bad client public value (A): ${A.toString(16)}`);
    }

    this._A = A;
  }

  get M1(): bigint {
    if (this._M1) {
      return this._M1;
    }

    throw new Error("Client evidence (M1) not set");
  }

  set M1(M1: bigint) {
    if (this._M1) {
      throw new Error(
        `Client evidence (M1) already set: ${this._M1.toString(16)}`,
      );
    }

    this._M1 = M1;
  }

  private _expectState(state: SRPClientSessionState): void {
    if (this.state !== state) {
      throw new Error(
        `State violation: Session must be in ${state} state but is in ${this.state}`,
      );
    }
  }
}
