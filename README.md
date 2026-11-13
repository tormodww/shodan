# Shodan-søk

Et enklere søkegrensesnitt oppå Shodan-API-et: søkebygger, grupperinger (fasetter) med drill-down, lagrede søk og CSV-eksport.

## Funksjoner

- **Søkebygger**: fritekst + filterrader (land, port, org, produkt, CVE, nett, HTTP-tittel, SSL …). `+`/`−` per rad for å inkludere/ekskludere. Ferdig spørring vises og kan kopieres.
- **Tell og grupper (gratis)**: bruker `/shodan/host/count`, som ikke koster query credits. Gir totalt antall og fasetter (land, org, port, produkt, CVE, ASN, OS, tag, domene …).
- **Drill-down**: hold musa over en verdi i en gruppering og trykk `+` (filtrer på den) eller `−` (ekskluder). `+` erstatter eksisterende filter på samme felt.
- **Hent treff**: `/shodan/host/search`, 100 per side. Koster 1 credit når søket har filtre eller side > 1 (vises på knappen). Treffene kan grupperes på klientsiden etter IP, org, land, port, produkt, ASN eller CVE, og eksporteres til CSV.
- **Detaljpanel**: banner, CVE-er sortert på CVSS, og «Slå opp hele verten» (`/shodan/host/{ip}`) for alle porter på verten.
- **Lagrede søk** og **historikk** i nettleserens localStorage, med eksport/import som JSON.
- Søket ligger i URL-en (`#…`), så du kan bokmerke eller dele lenker.
- Credits igjen vises øverst til høyre.

## Sikkerhet

API-nøkkelen ligger bare på serveren (env-variabel). Nginx legger på `key=` når den proxyer `/api/*` til `https://api.shodan.io`, så nøkkelen havner aldri i nettleseren. Proxyen tillater bare `GET`.
Merk: alle som når siden kan bruke nøkkelen din via proxyen. Kjør den på LAN/VPN, eller legg den bak autentisering (f.eks. reverse proxy med basic auth) hvis den eksponeres.

## Kjør med Docker (f.eks. Raspberry Pi)

```bash
cp .env.example .env        # sett SHODAN_API_KEY
docker compose up -d --build
# åpne http://<pi-ip>:8088
```

Imagene (`node:22-alpine`, `nginx:stable-alpine`) er multi-arch og fungerer på arm64.

## Utvikling

```bash
npm install
echo "SHODAN_API_KEY=din-nokkel" > .env.local
npm run dev                  # http://localhost:5173, Vite proxyer /api og legger på nøkkelen
npm run build
```

`SHODAN_UPSTREAM` kan settes for å peke dev-proxyen mot en mock i stedet for api.shodan.io.

## Struktur

```
src/shodan.ts       API-klient og typer
src/query.ts        filter-/fasettdefinisjoner, bygging av spørring, URL-hash
src/storage.ts      localStorage for lagrede søk og historikk
src/components.tsx  søkebygger, fasettpanel, resultattabell, detaljpanel
src/App.tsx         hovedside
docker/             nginx-konfig (template, env-substitusjon av nøkkelen)
```

Legg til nye filtre eller fasetter i `FILTERS` / `FACETS` i `src/query.ts`.
