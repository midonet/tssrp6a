// @flow
import { BigInteger } from "jsbn";

import { SRPConfig } from "./config";
import { bigIntegerToHex, hash, HexString } from "./utils";

// tslint:disable:variable-name
export class SRPSession {
  /**
   * SRPConfig used in this session.
   */
  private _config: SRPConfig;

  /**
   * Shared session key "S"
   */
  private _S?: BigInteger;

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

  get S(): BigInteger {
    if (this._S) {
      return this._S;
    }

    throw new Error("Shared Key (S) not set");
  }

  set S(S: BigInteger) {
    if (this._S) {
      throw new Error(
        `Shared key (S) already set: ${bigIntegerToHex(this._S)}`,
      );
    }

    this._S = S;
  }

  get sharedKey(): BigInteger {
    return this.S;
  }

  get hashedSharedKey(): HexString {
    return hash(this.config.parameters, this.sharedKey);
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
