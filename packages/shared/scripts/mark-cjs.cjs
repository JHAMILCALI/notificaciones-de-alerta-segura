// dist/cjs se interpreta como CommonJS aunque el paquete sea "type": "module".
require('node:fs').writeFileSync('dist/cjs/package.json', '{ "type": "commonjs" }\n');
