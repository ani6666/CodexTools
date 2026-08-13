import type { ReactNode } from 'react';

export function Card({ title, children }: { title: string; children: ReactNode }) {
  return <article className="card"><h3>{title}</h3><div className="card__body">{children}</div></article>;
}
