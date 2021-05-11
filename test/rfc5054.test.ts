import { BigInteger } from "jsbn";
import { SRPConfig } from "../src/config";
import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { SRPServerSession } from "../src/session-server";
import { createVerifier, HashWordArray, stringToWordArray } from "../src/utils";
import { test } from "./tests";

test("#SRP6aRFC5054", (t) => {
  t.plan(8);

  const N = new BigInteger(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
    16,
  );
  const G = new BigInteger("2");
  const parameters = new SRPParameters(N, G, SRPParameters.H.SHA1);
  const username = "alice";
  const password = "password123";

  class TestClientRoutines extends SRPRoutines {
    public computeIdentityHash(I: string, P: string): HashWordArray {
      return this.hash(stringToWordArray(`${I}:${P}`));
    }

    public generatePrivateValue(): BigInteger {
      return new BigInteger(
        "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393",
        16,
      ).mod(this.parameters.N);
    }
  }

  class TestServerRoutines extends SRPRoutines {
    public generatePrivateValue(): BigInteger {
      return new BigInteger(
        "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20",
        16,
      ).mod(this.parameters.N);
    }
  }

  const clientRoutines = new TestClientRoutines(parameters);
  const clientConfig = new SRPConfig(parameters, (_) => clientRoutines);

  const serverConfig = new SRPConfig(
    parameters,
    (p) => new TestServerRoutines(p),
  );

  const salt = new BigInteger("BEB25379D1A8581EB5A727673A2441EE", 16);
  const verifier = createVerifier(clientConfig, username, salt, password);

  t.equals(
    "7556aa045aef2cdd07abaf0f665c3e818913186f",
    clientRoutines.computeK().toString(16),
    "K",
  );
  t.equals(
    "94b7555aabe9127cc58ccf4993db6cf84d16c124",
    clientRoutines.computeX(username, salt, password).toString(16),
    "X step 1",
  );
  t.equals(
    verifier.toString(16),
    "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
    "Verifier",
  );
  const client = new SRPClientSession(clientConfig);
  client.step1(username, password);

  const server = new SRPServerSession(serverConfig);
  const B = server.step1(username, salt, verifier);
  const { A, M1 } = client.step2(salt, B);
  t.equals(
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
    A.toString(16),
    "A",
  );
  t.equals(
    "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
    B.toString(16),
    "B",
  );
  t.equals(
    "ce38b9593487da98554ed47d70a7ae5f462ef019",
    clientRoutines.computeU(A, B).toString(16),
    "U",
  );
  const M2 = server.step2(A, M1);
  client.step3(M2);

  t.equals(
    "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a",
    client.S.toString(16),
    "Premaster evidence",
  );
  t.equals(
    "94b7555aabe9127cc58ccf4993db6cf84d16c124",
    clientRoutines.computeXStep2(salt, client.identityHash).toString(16),
    "X step 2",
  );
});
