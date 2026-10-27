#!/usr/bin/env node
import { run } from './cli.ts';
import { CliError } from './errors.ts';

run(process.argv.slice(2), { out: (line) => console.log(line) }).catch((error: unknown) => {
  if (error instanceof CliError) {
    console.error(`Error: ${error.message}`);
  } else if (error instanceof Error && 'code' in error && String(error.code).startsWith('ERR_PARSE_ARGS')) {
    console.error(`Error: ${error.message}`);
  } else {
    console.error('Error inesperado:', error instanceof Error ? error.message : String(error));
  }
  process.exitCode = 1;
});
