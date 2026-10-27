import cp from 'node:child_process';

for (const b of ["s2/moto", "s2/shiro"]) {
  console.log("== Checking branch for skipped tests/rules:", b);
  const diff = cp.execSync(`git diff feat/semana-2...${b}`, { maxBuffer: 100 * 1024 * 1024 }).toString();
  const lines = diff.split('\n');
  const suspRegex = /^\+.*(\.skip\(|\.only\(|\bxit\(|\bxdescribe\(|eslint-disable|@ts-ignore|@ts-expect-error|passWithNoTests)/;
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    if (suspRegex.test(lines[i])) {
      count++;
      console.log(`[${b}] line ${i}: ${lines[i].trim()}`);
    }
  }
  console.log(`Total found in ${b}: ${count}`);
}
