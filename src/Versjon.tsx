import { useEffect, useState } from 'react';

/** Innholdet i /versjon.json, som lages når appen bygges på Pi-en (se Dockerfile). */
type VersjonData = { commit: string; commitDato: string; pr: number | null; bygget: string };

function formaterTid(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const dato = d.toLocaleDateString('nb-NO', { day: 'numeric', month: 'short', year: 'numeric' });
  const tid = d.toLocaleTimeString('nb-NO', { hour: '2-digit', minute: '2-digit' });
  return `${dato} kl. ${tid}`;
}

async function hentVersjon(): Promise<VersjonData | null> {
  try {
    const svar = await fetch('/versjon.json', { cache: 'no-cache' });
    if (svar.ok && svar.headers.get('content-type')?.includes('json')) return await svar.json();
  } catch {
    /* Ingen versjon å vise. */
  }
  return null;
}

/** Versjonen appen kjører (PR, ellers commit) og når den ble bygget. Vises ikke uten versjon.json (f.eks. i utvikling). */
export default function Versjon({ className }: { className?: string }) {
  const [versjon, setVersjon] = useState<VersjonData | null>(null);
  useEffect(() => {
    hentVersjon().then(setVersjon);
  }, []);
  if (!versjon) return null;
  return (
    <span className={className} title={`Commit ${versjon.commit} fra ${formaterTid(versjon.commitDato)}`}>
      Versjon {versjon.pr ?? versjon.commit} · bygget {formaterTid(versjon.bygget)}
    </span>
  );
}
