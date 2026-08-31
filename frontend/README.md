# OSINT Investigation Frontend

Interactive 3D investigation graph and dashboard for the OSINT platform.
The page always loads a saved fixture JSON on startup (`public/example-dns.json`)
so it works with no backend running; the search box in the header hits a
local FastAPI dev server that runs the real `collectors/dns` collector.

## Stack

- **React + TypeScript + Vite** -- fast dev loop, minimal config, strong typing against the collector's JSON schema.
- **react-force-graph-3d** (Three.js under the hood) -- purpose-built 3D node/link graph with orbit camera, zoom, and node picking already solved.
- **d3-force-3d** -- used directly for two forces: `forceRadial` (per-node radius by hop-distance from the target, driving the hierarchical/radial layout) and `forceCollide` (guarantees nodes never overlap). See `src/components/graph/sphereLayout.ts`.
- **FastAPI + uvicorn** (`backend/main.py`) -- the smallest real slice of the target React → FastAPI → DNS Collector architecture: one endpoint, no database, reuses `DNSCollector` unchanged.

No UI framework, state management library, or charting library was added -- the query performance chart is a plain CSS bar list, since one chart type doesn't justify a dependency.

## Install

```bash
cd frontend
npm install
```

The backend reuses the project's existing Python virtual environment; from
`OSINT/`:

```bash
pip install -r requirements.txt
```

## Run

Two processes, both from the `OSINT/` project root:

```bash
# Terminal 1 -- backend (powers the search box)
uvicorn backend.main:app --reload --port 8000

# Terminal 2 -- frontend
cd frontend && npm run dev
```

Open the printed local URL (typically http://localhost:5173). The page
loads the fixture immediately; type a domain/hostname/IP into the header
search box and click **Investigate** to run a live collection through the
backend. If the backend isn't running, searching shows a clear "could not
reach the investigation service" error with a **Retry** button -- the
fixture view is unaffected.

### Default DNS resolver

The backend defaults to `8.8.8.8`, configurable per-environment without
touching any code:

```bash
OSINT_DEFAULT_NAMESERVER=1.1.1.1 uvicorn backend.main:app --reload --port 8000
```

The collector itself never hardcodes a resolver -- `nameservers=None` means
"use the system resolver," which the backend selects if you pass
`?nameserver=system` on the endpoint directly. Whichever resolver was
actually used for a given investigation is always shown in the Overview
panel ("Resolver(s)"), sourced from the collection's own `queries[].resolver`.

## Where to put DNS JSON

The fixture lives at `frontend/public/example-dns.json` and is only used
for the initial page load / offline development. Regenerate it directly
from the Python collector if you want to change what loads by default:

```bash
# from the OSINT/ project root
python -m collectors.dns example.com --json --nameserver 8.8.8.8 > frontend/public/example-dns.json
```

For investigating arbitrary targets day-to-day, use the search box instead
(see Run, above) -- it never touches this file.

## How the JSON becomes graph nodes

`src/data/dnsToGraph.ts` is the only file that interprets DNS-specific
structure for the graph:

- `records` (each with `name`, `value`, `type`) is walked to produce
  `name -> value` edges labeled by record type (A, AAAA, NS, MX, CNAME, PTR).
  This is the source of truth for graph structure because it is the only
  place that records *which* name produced a given value (important for
  multi-hop chains like `nameserver -> its own IP`).
- `related_entities` is used only to classify what kind of thing a value is
  (ip / nameserver / mail_server / hostname), since the collector has
  already done that classification.
- SOA and CAA records describe metadata about a name rather than a
  relationship to another entity, so they stay in the Records panel only
  and are not turned into graph nodes.
- A null MX record (`MX 0 .`) is recognized and intentionally produces no
  mail-server node or edge -- it means "no mail service", not a relationship
  to the DNS root.

Nothing in this file is specific to `example.com`; run it on any
`DnsCollection` and it produces the matching graph.

## Making the graph expandable / collapsible

Two natural extension points, both already structurally supported:

1. **Per-kind visibility toggles** -- filter `graph.nodes`/`graph.edges` by
   `node.kind` before passing `graphData` to `InvestigationGraph` (e.g. hide
   `other` (TXT/attribute) nodes to declutter a large graph).
2. **Progressive disclosure** -- since edges are derived from `records`, a
   "second level" collector run (e.g. resolving one more hop) just needs to
   append more `DnsRecord`s to the same collection; `dnsToGraph` requires no
   changes to pick them up.

## Adding another entity type / collector

1. Add the new entity's TypeScript type under `src/types/` mirroring its
   collector's JSON (see `src/types/dns.ts` as the template).
2. Add its kind(s) to `EntityKind` in `src/types/graph.ts` and give it a
   color/size/label in `src/styles/entityStyle.ts` -- the graph and Legend
   pick this up automatically.
3. Write a `xToGraph(data): InvestigationGraph` function, following the same
   shape as `dnsToGraph`.
4. To combine multiple collectors into one graph, merge the `nodes`/`edges`
   arrays from each `xToGraph` call, de-duplicating by `GraphNode.id`
   (`${kind}:${value}` already namespaces IDs so the same IP discovered by
   DNS and by an RDAP collector merges into a single node).

## The two data sources, and where each is used

`src/components/App.tsx` holds two concrete `InvestigationDataSource`
instances (`src/data/InvestigationDataSource.ts`):

- `fixtureSource` (`FileDataSource`) -- only used for the automatic load on
  first page render.
- `apiSource` (`ApiDataSource`, pointed at `http://localhost:8000/api`) --
  used for every search-box submission.

Neither the graph nor the panels know which one supplied the data; they
only ever depend on the resolved `DnsCollection` object. Moving the search
box's target to a production backend later means changing `apiSource`'s
base URL (and, eventually, deploying `backend/main.py`'s logic behind
whatever auth/routing the production API needs) -- no other file changes.

## What to build next

1. Persist collections to PostgreSQL behind the backend (`backend/main.py`
   currently returns the collector's result directly with no storage layer
   -- frontend should still never talk to Postgres directly).
2. Support IPv4/IPv6 targets end-to-end in the UI (the collector and
   `dnsToGraph` already handle PTR lookups; the search box doesn't yet
   distinguish target types).
3. A second collector (RDAP or Certificate Transparency is a natural next
   step) with its own `xToGraph` function, merged into the same graph as
   described above -- `backend/main.py` would grow a second endpoint per
   collector rather than one shared "investigate everything" endpoint, to
   keep each collector's config/error handling independent.
4. A dedicated settings UI for resolver/timeout/lifetime, if
   `OSINT_DEFAULT_NAMESERVER` plus the existing Overview "Resolver(s)"
   display stops being enough.
