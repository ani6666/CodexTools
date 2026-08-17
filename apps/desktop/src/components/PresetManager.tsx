import { useEffect, useState, type FormEvent } from 'react';
import type { IdentitySummary, PresetSummary } from '../ipc';
import { Button } from './Button';

interface Props { identity: IdentitySummary | null; presets: PresetSummary[]; loading: boolean; busy: boolean; t: (key: string) => string; onSave: (identity: IdentitySummary, preset: PresetSummary | null, name: string, modelId: string) => Promise<void> }

export function PresetManager({ identity, presets, loading, busy, t, onSave }: Props) {
  const [selectedId, setSelectedId] = useState<string>('new');
  const selected = presets.find((item) => item.presetId === selectedId) ?? null;
  const [name, setName] = useState('');
  const [modelId, setModelId] = useState('');
  useEffect(() => { setSelectedId('new'); setName(''); setModelId(''); }, [identity?.identityId]);
  useEffect(() => { if (selected) { setName(selected.name); setModelId(selected.modelId); } else { setName(''); setModelId(''); } }, [selected?.presetId]);
  const submit = async (event: FormEvent) => { event.preventDefault(); if (identity && name.trim() && modelId.trim()) await onSave(identity, selected, name, modelId); };
  return <section id="model-presets" className="work-panel" aria-labelledby="presets-title" aria-busy={loading}>
    <div className="work-panel__heading"><div><h2 id="presets-title">{t('m33.presets.title')}</h2><p>{t('m33.presets.description')}</p></div></div>
    {!identity ? <p className="empty-copy" role="status">{t('m33.presets.chooseIdentity')}</p> : <form className="preset-form" onSubmit={submit}><label htmlFor="preset-choice">{t('m33.presets.choiceLabel')}</label><select id="preset-choice" value={selectedId} onChange={(event) => setSelectedId(event.target.value)}><option value="new">{t('m33.presets.createNew')}</option>{presets.map((preset) => <option key={preset.presetId} value={preset.presetId}>{preset.name}{preset.isDefault ? ` · ${t('m33.presets.default')}` : ''}</option>)}</select><div className="form-grid"><label htmlFor="preset-name">{t('m33.presets.nameLabel')}</label><input id="preset-name" value={name} maxLength={80} onChange={(event) => setName(event.target.value)} required /><label htmlFor="model-id">{t('m33.presets.modelLabel')}</label><input id="model-id" value={modelId} maxLength={128} onChange={(event) => setModelId(event.target.value)} aria-describedby="model-id-hint" required /><span id="model-id-hint">{t('m33.presets.modelHint')}</span></div><Button variant="primary" type="submit" disabled={busy || !name.trim() || !modelId.trim()}>{selected ? t('m33.action.updateBind') : t('m33.action.createBind')}</Button></form>}
  </section>;
}
