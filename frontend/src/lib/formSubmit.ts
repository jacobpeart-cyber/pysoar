import { describeActionError } from './automationErrors';

/**
 * FormModal shows `err.message` (or a string `detail`) for a failed submit;
 * a 422 validation list or a structured `{error, detail}` body would not
 * render. Re-throw such failures as one readable line with the server's code
 * and every itemised reason.
 */
export async function readableSubmit<T>(p: Promise<T>): Promise<T> {
  try {
    return await p;
  } catch (err) {
    const { summary, items } = describeActionError(err);
    throw new Error(items.length ? `${summary} (${items.join('; ')})` : summary);
  }
}
