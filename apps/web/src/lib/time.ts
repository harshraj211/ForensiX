const TIMEZONE_SUFFIX = /(?:Z|[+-]\d{2}:\d{2})$/i;

export function utcDate(value: string): Date {
  return new Date(TIMEZONE_SUFFIX.test(value) ? value : `${value}Z`);
}

export function formatUtcAsLocal(value: string): string {
  const date = utcDate(value);
  if (Number.isNaN(date.getTime())) return "Invalid timestamp";
  return date.toLocaleString(undefined, { timeZoneName: "short" });
}
