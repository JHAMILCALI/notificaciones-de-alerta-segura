/**
 * Catálogo de alertas para Bolivia (D-4, opción C). Prototipo académico: estos valores no representan
 * comunicaciones oficiales del SENAMHI, VIDECI ni de ninguna institución.
 */

/** Los nueve departamentos del Estado Plurinacional de Bolivia. */
export const DEPARTAMENTOS = [
  'LA_PAZ',
  'ORURO',
  'POTOSI',
  'COCHABAMBA',
  'CHUQUISACA',
  'TARIJA',
  'SANTA_CRUZ',
  'BENI',
  'PANDO',
] as const;
export type Departamento = (typeof DEPARTAMENTOS)[number];

export const DEPARTAMENTO_ETIQUETAS: Readonly<Record<Departamento, string>> = {
  LA_PAZ: 'La Paz',
  ORURO: 'Oruro',
  POTOSI: 'Potosí',
  COCHABAMBA: 'Cochabamba',
  CHUQUISACA: 'Chuquisaca',
  TARIJA: 'Tarija',
  SANTA_CRUZ: 'Santa Cruz',
  BENI: 'Beni',
  PANDO: 'Pando',
};

/** Fenómenos climáticos relevantes en el altiplano, los valles y el oriente bolivianos. */
export const TIPOS_ALERTA = [
  'LLUVIAS_INTENSAS',
  'TORMENTA_ELECTRICA',
  'GRANIZADA',
  'NEVADA',
  'HELADA',
  'OLA_DE_FRIO',
  'OLA_DE_CALOR',
  'VIENTOS_FUERTES',
  'INUNDACION',
  'DESBORDE_DE_RIO',
  'MAZAMORRA',
  'SEQUIA',
  'INCENDIO_FORESTAL',
  'RADIACION_UV_EXTREMA',
] as const;
export type TipoAlerta = (typeof TIPOS_ALERTA)[number];

export const TIPO_ALERTA_ETIQUETAS: Readonly<Record<TipoAlerta, string>> = {
  LLUVIAS_INTENSAS: 'Lluvias intensas',
  TORMENTA_ELECTRICA: 'Tormenta eléctrica',
  GRANIZADA: 'Granizada',
  NEVADA: 'Nevada',
  HELADA: 'Helada',
  OLA_DE_FRIO: 'Ola de frío (surazo)',
  OLA_DE_CALOR: 'Ola de calor',
  VIENTOS_FUERTES: 'Vientos fuertes',
  INUNDACION: 'Inundación',
  DESBORDE_DE_RIO: 'Desborde de río',
  MAZAMORRA: 'Mazamorra (flujo de lodo)',
  SEQUIA: 'Sequía',
  INCENDIO_FORESTAL: 'Incendio forestal',
  RADIACION_UV_EXTREMA: 'Radiación UV extrema',
};

/** Niveles de alerta por color, como se comunican en Bolivia (el verde equivale a «sin alerta»). */
export const NIVELES_ALERTA = ['AMARILLA', 'NARANJA', 'ROJA'] as const;
export type NivelAlerta = (typeof NIVELES_ALERTA)[number];

export const NIVEL_ALERTA_ETIQUETAS: Readonly<Record<NivelAlerta, string>> = {
  AMARILLA: 'Alerta amarilla',
  NARANJA: 'Alerta naranja',
  ROJA: 'Alerta roja',
};

/** Bolivia usa UTC−4 todo el año. Se firma en UTC; la PWA muestra en esta zona. */
export const ZONA_HORARIA_BOLIVIA = 'America/La_Paz';
export const LOCALE_BOLIVIA = 'es-BO';

/** Vigencia de una alerta: el borrador guarda horas y el servidor fija `expira_en` al publicar. */
export const VIGENCIA_HORAS_MIN = 1;
export const VIGENCIA_HORAS_MAX = 72;
