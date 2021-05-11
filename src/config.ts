import { SRPParameters } from "./parameters";
import { SRPRoutines, SRPRoutinesFactory } from "./routines";

export class SRPConfig {
  private _parameters: SRPParameters;
  private _routines: SRPRoutines;

  constructor(parameters: SRPParameters, routinesFactory: SRPRoutinesFactory) {
    this._parameters = parameters;
    this._routines = routinesFactory(parameters);
  }

  get parameters(): SRPParameters {
    return this._parameters;
  }

  get routines(): SRPRoutines {
    return this._routines;
  }
}
