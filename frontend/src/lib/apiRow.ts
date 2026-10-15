/**
 * A JSON row returned by the API whose shape the page reads field by field.
 * Pages render each field honestly (null -> "not available"), so a loose
 * record type is used instead of repeating `any` on every handler.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Row = Record<string, any>;
