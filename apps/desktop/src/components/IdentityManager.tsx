import { useEffect, useState, type FormEvent } from 'react';
import type { IdentitySummary } from '../ipc';
import { Button } from './Button';

interface Props { identities: IdentitySummary[]; selectedId: string | null; loading: boolean; busy: boolean; t: (key: string) => string; onRefresh: () => void; onSelect: (id: string) => void; onRename: (identity: IdentitySummary, name: string) => Promise<void> }

export function IdentityManager({ identities, selectedId, loading, busy, t, onRefresh, onSelect, onRename }: Props) {
  const selected = identities.find((item) => item.identityId === selectedId) ?? null;
  const [name, setName] = useState('');
  useEffect(() => setName(selected?.name ?? ''), [selected?.identityId, selected?.name]);
  const submit = async (event: FormEvent) => { event.preventDefault(); if (selected && name.trim()) await onRename(selected, name); };
  return <section id="saved-identities" className="work-panel" aria-labelledby="identities-title" aria-busy={loading}>
    <div className="work-panel__heading"><div><h2 id="identities-title">{t('m33.identities.title')}</h2><p>{t('m33.identities.description')}</p></div><Button onClick={onRefresh} disabled={busy}>{t('m33.action.refresh')}</Button></div>
    {identities.length === 0 ? <p className="empty-copy" role="status">{t('m33.identities.empty')}</p> : <div className="identity-layout"><div className="selection-list" role="list" aria-label={t('m33.identities.listLabel')}>{identities.map((identity) => <button type="button" role="listitem" className={identity.identityId === selectedId ? 'selection-item selection-item--active' : 'selection-item'} key={identity.identityId} onClick={() => onSelect(identity.identityId)}><strong>{identity.name}</strong><span>{identity.providerName} · {t(`m33.auth.${identity.authMode}`)}</span><span className="status-chip">{t(`m33.identityStatus.${identity.status}`)}</span></button>)}</div>{selected && <form className="edit-form" onSubmit={submit}><label htmlFor="identity-name">{t('m33.identities.nameLabel')}</label><input id="identity-name" value={name} maxLength={80} onChange={(event) => setName(event.target.value)} aria-describedby="identity-name-hint" required /><span id="identity-name-hint">{t('m33.identities.nameHint')}</span><Button variant="primary" type="submit" disabled={busy || !name.trim()}>{t('m33.action.rename')}</Button></form>}</div>}
  </section>;
}
