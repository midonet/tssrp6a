import tapDiff from "tap-diff";
import tape from "tape-promise/tape";

if (!process.env.TAPE_RAW_OUTPUT) {
  tape.createStream().pipe(tapDiff()).pipe(process.stdout);
}

tape.onFinish(() => {
  process.exit(0);
});

export const test = tape;
