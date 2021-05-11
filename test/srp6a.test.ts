import { SRPConfig } from "../src/config";
import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { SRPServerSession } from "../src/session-server";
import {
  createVerifierAndSalt,
  generateRandomString,
  HashWordArray,
  stringToWordArray,
} from "../src/utils";
import { test } from "./tests";

const testParameters = new SRPParameters();
class SRP6aRoutines extends SRPRoutines {
  public computeIdentityHash(I: string, P: string): HashWordArray {
    return this.hash(stringToWordArray(`${I}:${P}`));
  }
}
const srp6aConfig = new SRPConfig(testParameters, (p) => new SRP6aRoutines(p));

test("#SRP6aSession success", (t) => {
  t.plan(1);

  const testUsername = generateRandomString(10);
  const testPassword = generateRandomString(15);

  // Sign up
  // salt and verifier are generated by client during signup
  // verifier is read from server storage for server.step1
  const { s: salt, v: verifier } = createVerifierAndSalt(
    srp6aConfig,
    testUsername,
    testPassword,
  );

  // Sign in
  const srp6aClient = new SRPClientSession(srp6aConfig);
  srp6aClient.step1(testUsername, testPassword);

  const server = new SRPServerSession(srp6aConfig);
  // server gets identifier from client, salt+verifier from db (from signup)
  const B = server.step1(testUsername, salt, verifier);

  // client gets challenge B from server step1 and sends prove M1 to server
  const { A, M1 } = srp6aClient.step2(salt, B);

  // servers checks client prove M1 and sends server prove M2 to client
  const M2 = server.step2(A, M1);

  // client ensures server identity
  srp6aClient.step3(M2);
  t.pass(`user:${testUsername}, password:${testPassword}, salt: ${salt}`);
});

test("#SRP6aSession config mismatch", (t) => {
  t.plan(1);

  const testUsername = "testUser";
  const testPassword = "testPassword";

  const defaultConfig = new SRPConfig(
    testParameters,
    (p) => new SRPRoutines(p),
  );

  // Sign up is done using SRP6a verifier
  const { s: salt, v: verifier } = createVerifierAndSalt(
    srp6aConfig,
    testUsername,
    testPassword,
  );

  // Sign in
  const defaultClient = new SRPClientSession(defaultConfig);
  defaultClient.step1(testUsername, testPassword);

  // server gets identifier from client, salt+verifier from db (from signup)
  const serverSession = new SRPServerSession(srp6aConfig);
  const B = serverSession.step1(testUsername, salt, verifier);

  // client gets challenge B from server step1 and sends prove M1 to server
  const { A, M1 } = defaultClient.step2(salt, B);

  t.throws(() => serverSession.step2(A, M1), /bad client credentials/i);
});
