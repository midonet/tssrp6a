import tape from "tape-promise/tape";

if (!process.env["NYC_PROCESS_ID"]) {
  const tapDiff: () => any = require("tap-diff"); // eslint-disable-line @typescript-eslint/no-var-requires
  tape.createStream().pipe(tapDiff()).pipe(process.stdout);
}

tape.onFinish(() => {
  process.exit(0);
});

export const test = tape;
