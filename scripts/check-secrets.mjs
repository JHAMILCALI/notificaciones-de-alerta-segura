import cp from 'node:child_process';

for (const b of ["s2/moto", "s2/shiro"]) {
  console.log("== Checking branch:", b);
  const log = cp.execSync(`git log -p feat/semana-2..${b}`, { maxBuffer: 100 * 1024 * 1024 }).toString();
  const secretRegex = /BEGIN (?:EC |ENCRYPTED )?PRIVATE KEY|"d"\s*:\s*"|APP_DB_PASSWORD=[^<\s]+|CSRF_SECRET=[0-9a-f]{32,}/g;
  let match;
  let count = 0;
  while ((match = secretRegex.exec(log)) !== null) {
    count++;
    const lineStart = log.lastIndexOf("\n", match.index);
    const lineEnd = log.indexOf("\n", match.index);
    const line = log.substring(lineStart, lineEnd);
    console.log(`[${b}] MATCH ${count}: ${match[0]} --> ${line.trim()}`);
  }
  if (count === 0) {
    console.log(`[${b}] No pattern matches in diff.`);
  }

  const tree = cp.execSync(`git ls-tree -r --name-only ${b}`).toString();
  const fileRegex = /(^|\/)secrets\/|\.pem$|\.key$|\.private\.jwk$/gm;
  let fMatch;
  let fCount = 0;
  while ((fMatch = fileRegex.exec(tree)) !== null) {
    fCount++;
    console.log(`[${b}] DANGEROUS FILE: ${fMatch[0]}`);
  }
  if (fCount === 0) {
    console.log(`[${b}] No dangerous file extensions in git tree.`);
  }
}
