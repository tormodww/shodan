import { newId, type QueryState } from './query';

type F = [key: string, value: string, negate?: boolean];

function preset(text: string, filters: F[], facets = ['country', 'org', 'port', 'product']): QueryState {
  return {
    text,
    filters: filters.map(([key, value, negate]) => ({ id: newId(), key, value, negate: !!negate })),
    facets,
    facetSize: 10,
  };
}

export interface Preset {
  group: string;
  name: string;
  description: string;
  state: QueryState;
}

/** Forhåndsdefinerte Shodan-søk (krever betalt API-nivå for filtre). */
export const SHODAN_PRESETS: Preset[] = [
  // Eksponerte tjenester i Norge
  { group: 'Eksponert i Norge', name: 'Åpent RDP', description: 'Remote Desktop rett mot internett', state: preset('', [['country', 'NO'], ['port', '3389']], ['org', 'city', 'os']) },
  { group: 'Eksponert i Norge', name: 'SMB / fildeling', description: 'Port 445 åpen', state: preset('', [['country', 'NO'], ['port', '445']], ['org', 'os', 'city']) },
  { group: 'Eksponert i Norge', name: 'Telnet', description: 'Ukryptert fjerninnlogging', state: preset('', [['country', 'NO'], ['port', '23']], ['org', 'product', 'city']) },
  { group: 'Eksponert i Norge', name: 'VNC uten passord', description: 'VNC med autentisering skrudd av', state: preset('"authentication disabled"', [['country', 'NO'], ['port', '5900,5901']], ['org', 'city']) },
  { group: 'Eksponert i Norge', name: 'Databaser', description: 'MongoDB, Elasticsearch, Redis, MySQL, Postgres', state: preset('', [['country', 'NO'], ['port', '27017,9200,6379,3306,5432']], ['port', 'product', 'org']) },
  { group: 'Eksponert i Norge', name: 'Industri / ICS', description: 'SCADA, Modbus, BACnet m.m.', state: preset('', [['country', 'NO'], ['tag', 'ics']], ['product', 'port', 'org']) },
  { group: 'Eksponert i Norge', name: 'Webkamera', description: 'Skjermbilder klassifisert som webcam', state: preset('', [['country', 'NO'], ['screenshot.label', 'webcam']], ['org', 'city', 'product']) },
  // Sårbarhet og hygiene
  { group: 'Sårbarhet og hygiene', name: 'Kjent sårbare verter (NO)', description: 'Verter med minst én CVE', state: preset('', [['country', 'NO'], ['has_vuln', 'true']], ['vuln', 'product', 'org']) },
  { group: 'Sårbarhet og hygiene', name: 'Utløpte SSL-sertifikater (NO)', description: 'ssl.cert.expired:true', state: preset('', [['country', 'NO'], ['ssl.cert.expired', 'true']], ['org', 'ssl.version']) },
  { group: 'Sårbarhet og hygiene', name: 'Gammel TLS (NO)', description: 'Servere som fortsatt tilbyr TLS 1.0', state: preset('ssl.version:tlsv1', [['country', 'NO']], ['org', 'product']) },
  { group: 'Sårbarhet og hygiene', name: 'Selvsignerte sertifikater (NO)', description: 'tag:self-signed', state: preset('', [['country', 'NO'], ['tag', 'self-signed']], ['org', 'port']) },
  // Admin-flater og infrastruktur
  { group: 'Admin-flater', name: 'Jenkins', description: 'Jenkins-dashbord', state: preset('', [['http.title', 'Dashboard [Jenkins]']], ['country', 'org', 'version']) },
  { group: 'Admin-flater', name: 'Grafana', description: 'Grafana-innlogging', state: preset('', [['http.title', 'Grafana']], ['country', 'org', 'version']) },
  { group: 'Admin-flater', name: 'Kubernetes API', description: 'Eksponerte k8s API-servere', state: preset('', [['product', 'Kubernetes']], ['country', 'org', 'version']) },
  { group: 'Admin-flater', name: 'Docker API', description: 'Docker-daemon på 2375', state: preset('', [['port', '2375'], ['product', 'Docker']], ['country', 'org', 'version']) },
  { group: 'Admin-flater', name: 'Fortinet-VPN (NO)', description: 'FortiGate SSL-VPN', state: preset('', [['country', 'NO'], ['product', 'FortiGate']], ['org', 'version', 'vuln']) },
  { group: 'Admin-flater', name: 'Home Assistant', description: 'Home Assistant mot internett', state: preset('', [['http.title', 'Home Assistant']], ['country', 'org']) },
  // Statistikk
  { group: 'Oversikt', name: 'Norge totalt', description: 'Alt i Norge, gruppert', state: preset('', [['country', 'NO']], ['org', 'port', 'product', 'os', 'city']) },
  { group: 'Oversikt', name: 'Mest brukte webservere (NO)', description: 'Port 80/443 per produkt', state: preset('', [['country', 'NO'], ['port', '80,443']], ['product', 'version', 'http.component']) },
];

/** Forhåndsdefinerte InternetDB-oppslag (gratis, ingen nøkkel). */
export const IDB_PRESETS: { name: string; description: string; input: string }[] = [
  { name: 'Store norske nettsteder', description: 'Medier og tjenester', input: 'vg.no nrk.no finn.no dagbladet.no aftenposten.no e24.no' },
  { name: 'Norske banker', description: 'Offentlige nettsider', input: 'dnb.no sparebank1.no nordea.no handelsbanken.no' },
  { name: 'Offentlig sektor', description: 'Etater og kommuner', input: 'nav.no skatteetaten.no altinn.no regjeringen.no oslo.kommune.no' },
  { name: 'Offentlige DNS-resolvere', description: 'Cloudflare, Google, Quad9', input: '1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9' },
  { name: 'Eksempel-nett /28', description: '16 adresser i et Google-nett', input: '8.8.8.0/28' },
];
