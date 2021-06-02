import { SRPParameters } from "./parameters";
import { SRPRoutines } from "./routines";
import { SRPClientSessionStep1, SRPClientSessionStep2 } from "./session-client";
import { SRPServerSessionStep1 } from "./session-server";

/**
 * Crude JSON-based deserialization that has just enough exceptions for tssrp6a
 * classes.
 * Needs the serialization string and the target class prototype, e.g.
 * `SRPServerSessionStep1.prototype`.
 */
export function deserialize<
  T extends
    | SRPServerSessionStep1
    | SRPClientSessionStep1
    | SRPClientSessionStep2,
>(str: string, proto: T): T {
  const obj = JSON.parse(str, (key, value) => {
    switch (key) {
      case "routines":
        value.__proto__ = SRPRoutines.prototype;
        return value;
      case "parameters":
        value.__proto__ = SRPParameters.prototype;
        return value;
      case "":
      case "NBits":
      case "primeGroup":
      case "identifier":
      case "I":
        return value;
      case "IH":
        return new Uint8Array(JSON.parse(value)).buffer;
      case "H":
        return SRPParameters.H[value];
      default:
        return BigInt(value);
    }
  });
  obj.__proto__ = proto;
  return obj;
}

/**
 * Crude JSON-based serialization that has just enough exceptions for tssrp6a
 * classes.
 */
export function serialize(
  step: SRPServerSessionStep1 | SRPClientSessionStep1 | SRPClientSessionStep2,
): string {
  return JSON.stringify(step, (_key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    } else if (value instanceof ArrayBuffer) {
      return JSON.stringify(Array.from(new Uint8Array(value)));
    } else if (typeof value === "function") {
      for (const [key, fn] of Object.entries(SRPParameters.H)) {
        if (value === fn) {
          return key;
        }
      }
      throw new Error("cannot serialize unknown hash function");
    }
    return value;
  });
}
