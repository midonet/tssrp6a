import { SRPConfig } from "./config";

export class SRPSession {
  /**
   * SRPConfig used in this session.
   */
  private _config: SRPConfig;

  /**
   * Shared session key "S"
   */
  private _S?: bigint;

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

  constructor(config: SRPConfig, timeoutMillis?: number) {
    this._config = config;
    this._timeoutMillis = timeoutMillis;
    this._timedOut = false;
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
    return this.config.routines.hashAsBigInt(this.S);
  }

  get config(): SRPConfig {
    return this._config;
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
}
