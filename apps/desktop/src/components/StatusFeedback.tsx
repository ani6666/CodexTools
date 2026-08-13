import type { DisplayState } from '../shell-state';

export function StatusFeedback({ state, title, body }: { state: DisplayState; title: string; body: string }) {
  return <section className={`status-feedback status-feedback--${state}`} role="status" aria-live="polite" aria-atomic="true" aria-busy={state === 'loading'}><span className="status-feedback__indicator" aria-hidden="true" /><div><h3>{title}</h3><p>{body}</p></div></section>;
}
