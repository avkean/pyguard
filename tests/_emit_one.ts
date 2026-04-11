import { obfuscatePythonCode } from "../lib/obfuscate";
import { writeFileSync } from "fs";
const out = obfuscatePythonCode('print("hi")\n');
writeFileSync("/tmp/test_stub.py", out);
