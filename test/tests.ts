import tape from "tape-promise/tape";
const tapDiff: () => any = require("tap-diff"); // eslint-disable-line @typescript-eslint/no-var-requires

if (!process.env["TAPE_RAW_OUTPUT"]) {
  tape.createStream().pipe(tapDiff()).pipe(process.stdout);
}

tape.onFinish(() => {
  process.exit(0);
});

export const test = tape;
