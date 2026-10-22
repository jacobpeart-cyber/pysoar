import clsx from 'clsx';
import { splitPrivateRefusal } from './types';

/**
 * A message the server recorded (test result, execution error, install
 * error). A private-address refusal is split so the allow-list instruction
 * (naming OUTBOUND_PRIVATE_ALLOWLIST) sits on its own line; the words are the
 * server's, nothing is added.
 */
export default function ServerMessage({
  text,
  className,
  as: Tag = 'p',
}: {
  text: string | null | undefined;
  className?: string;
  as?: 'p' | 'span';
}) {
  if (!text) return null;
  const { message, hint } = splitPrivateRefusal(text);
  if (!hint) return <Tag className={className}>{message}</Tag>;
  return (
    <Tag className={clsx(className, 'block')}>
      <span className="block">{message}</span>
      <span className="block mt-1 text-xs font-medium text-amber-800 dark:text-amber-200" data-testid="allowlist-hint">
        {hint}
      </span>
    </Tag>
  );
}
