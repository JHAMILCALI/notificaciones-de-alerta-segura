/** Error esperado de la CLI: se muestra sin traza y termina con código 1. */
export class CliError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'CliError';
    this.code = code;
  }
}
