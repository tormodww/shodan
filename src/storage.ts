import type { QueryState } from './query';

export interface SavedSearch {
  id: string;
  name: string;
  state: QueryState;
  createdAt: string;
}

export interface HistoryEntry {
  query: string;
  state: QueryState;
  total: number;
  at: string;
}

const SAVED_KEY = 'shodan-sok.saved';
const HISTORY_KEY = 'shodan-sok.history';

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* privat modus e.l. */
  }
}

export const loadSaved = () => read<SavedSearch[]>(SAVED_KEY, []);
export const storeSaved = (s: SavedSearch[]) => write(SAVED_KEY, s);
export const loadHistory = () => read<HistoryEntry[]>(HISTORY_KEY, []);
export const storeHistory = (h: HistoryEntry[]) => write(HISTORY_KEY, h.slice(0, 30));

export function downloadFile(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
