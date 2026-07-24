Scope Creep
=====
A mass target enumeration tool

Installation
=====
Requires [Node.js and npm](https://nodejs.org/en/download/).

Clone the repo and install dependencies:
```
git clone https://github.com/fkasler/scope_creep.git
cd scope_creep
npm install
```

Getting Started
=====
Start the server and open [http://localhost:3000](http://localhost:3000) in Chrome:
```
node index.js
```

Session Persistence & Recovery
=====

Scope Creep auto-saves your working graph and lets you switch between past sessions.

- **Auto-save:** every graph change — adding nodes, running lookups, connecting, deleting, and any metadata that lands on a node — is saved automatically in the background (debounced). Nothing to click.
- **Refresh recovery:** reload or reopen the tab and your last session is restored — nodes, links, connections, labels, and metadata.
- **Session queue:** the **⧉ Sessions** button (or the "Sessions" help-menu row) opens the queue, where you can start a **New Session**, switch to a saved one, or rename/delete sessions.
- **Storage:** `localStorage` is the live source of truth; every save is mirrored to `sessions/` on the server as a backup. Server backups appear in the queue tagged `backup` — useful after clearing browser data or moving machines. The `sessions/` directory is created on server start and is git-ignored.

This is separate from **Export Graph (E)** / **Open Graph (O)**, which save or load a named graph file.

Usage/Modules
=====

- Built for Chrome; key bindings and some features may not work in other browsers.
- "Safety" Mode is on by default to prevent accidental mass queries against CIDR ranges, port scans, and ping sweeps. Turn it off when you need those.
- Trigger modules by clicking them in the help menu or with the key bindings below.
- Select multiple nodes by clicking their rows in the stats/list view or with node search.
- Node search/find (f) supports JavaScript regular expressions (e.g. `domain.com` matches the domain and its subdomains; `^domain.com` matches only the domain). [regex reference](https://eloquentjavascript.net/09_regexp.html)
- Add API keys/cookies for the services you use — [Shodan](https://www.shodan.io/), [Whoxy](https://www.whoxy.com/reverse-whois/), [LinkedIn li_at](https://www.linkedin.com/), [Hunter.io](https://hunter.io/users/sign_up), and [Flare](https://flare.io/). Each is saved in a cookie when you click out of its input and persists between reloads.
- For automated dorking, add a [Google Programmable Search](https://developers.google.com/custom-search/v1/overview) key and its engine id (`cx`) and a [GitHub token](https://github.com/settings/tokens) (code search requires auth). An optional [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) speeds up CVE Lookup. All are optional — the Dork Generator and keyless CVE Lookup work without them.
- The Flare tenant id is optional: leave it blank for your account's default tenant, or set it to scope lookups. Use the "Status" button to validate your key/tenant.
- Toolbar toggles: **List View** (tabular vs. graph), **theme** (🌙/☀️), and **node labels** (off/all/selected). Preferences persist in cookies.
- The li_at cookie is LinkedIn's session cookie, required for the LinkedIn scraper. The [EditThisCookie](http://www.editthiscookie.com/) Chrome extension can grab it.

### Add Node(a):
Selects and clears the input box; type a node name and press enter to add it to the graph.

### Help(h):
Toggles the help window.

### Hide Stats(H):
Toggles the stats list.

### Toggle List View(z):
Switches between the force-directed graph and a tabular List View of the same data — grouped by type, searchable/sortable, with "Show in Graph" to jump back. For credential nodes, the **Identity** column shows the account a leaked secret is tied to (credentials are stored as `identity : secret`).

### Toggle Theme(🌙/☀️):
Flips the interface between dark and light. Saved in a cookie.

### Toggle Labels(🏷️):
Node labels are hidden by default and appear on hover. The **Labels** button cycles a persistent mode:
- **Off** — hover-only (default).
- **All** — every label pinned (busy on large graphs).
- **Selected** — labels pinned for the selected nodes only.

Saved in a cookie.

### Connect Nodes(c):
Select a node, press 'c', then select another to connect them. Press 'c' again to cancel.

### Copy Nodes to Clipboard(y):
Copies the selected nodes' contents to the clipboard — e.g. an addresses list for phishing.

### Select First Connections(UP Arrow):
Adds every node directly connected to the selection. Press repeatedly to walk outward one hop at a time — e.g. to grab everything attached to a domain before a mass operation.

### Export Nodes(e):
Exports the selected nodes to a file. If the file name contains 'finding', they're exported in the format Engage expects for finding imports (e.g. open-port nodes into an "Internet accessible authentication prompts" finding).

### Export Graph(E):
Exports the entire graph as JSON — for saving progress or sharing.

### Select Nodes based on # of connections (0-9):
Selects nodes by how many others connect to them — useful for mass operations.

### Open Scope File(o):
Imports a scope file of domains, subdomains, IPs, and CIDR ranges. Select a parent node first for the entries to attach to. Supports wildcards (e.g. `scope_file*` imports scope_file1.txt, scope_file2.txt, …).

### Open Graph(O):
Opens a saved graph. Supports wildcards, which is handy for combining graphs into one scope graph.

### Delete Nodes(d):
Deletes the selected nodes.

### Delete Unselected Nodes(D):
Deletes everything except the selected nodes — pairs well with (f).

### Undo Deleted Nodes(u):
Restores connections to the selected nodes — useful for paring down and rebuilding graphs by search criteria.

### Change Node Type(U):
Updates the node type for a single selected node.

### Whois Lookup(w):
Whois lookup on the selected IP node.

### Whoxy Reverse Whois Lookup(W):
Searches the Whoxy API for related domains by organization name, technical-contact email, or keyword. For domain nodes like "example.com", choose option (c) when prompted.

### MX Query(m):
DNS MX lookup on the selected nodes — a quick list of mail servers.

### Reverse DNS Lookup(r):
Reverse DNS on the selected nodes. For a CIDR range, it looks up every IP in the range — a fast way to find hosts on a network.

### Mass Reverse DNS Lookup(R):
Reverse DNS on all IP nodes in the graph.

### TXT Records(t):
DNS TXT lookup on the selected nodes; also parses CIDR ranges, hosts, and domains out of SPF records.

### Mass TXT Records(T):
Like (t), against all domain nodes — good for enumerating sprawling SPF records.

### Name Servers(n):
DNS NS lookup on the selected nodes.

### Generate Emails(g):
Generates emails from all person nodes. Leave the domain blank to omit the @ and produce usernames instead.

### Generate Phishmonger Target CSV(G):
Copies a social-engineering targets CSV to the clipboard — pairs with the LinkedIn scraper and Hunter.io results.

### Convert IP Range to CIDR Node(C):
Turns a selected IP-range node (e.g. "192.168.0.0-192.168.0.255") into a CIDR node (e.g. "192.168.0.0/24") when the range aligns to a network boundary — ready to ping sweep or port scan.

### View Website in New Tab(v):
Opens a new Chrome tab for each selected node.

### Mass View Website in New Tab(V):
Opens a tab for every subdomain node in the graph.

### ASN search(A):
Finds IP ranges belonging to an organization via the [asnlookup.com](http://asnlookup.com/) API. Forward lookups by organization name only.

### ARIN Org → Netblocks/ASNs:
Searches ARIN's [Whois-RWS](https://whois.arin.net/) registry by the selected node's name and pulls the netblocks and ASNs registered to each matching org — the authoritative way to turn a target org name into IP scope. Each match becomes an organization node; its netblocks come back as **CIDR nodes** (ready to ping sweep or port scan) and its ASNs as info nodes. Menu-triggered. ARIN covers North America; other regions are registered with RIPE/APNIC/LACNIC/AFRINIC.

### ARIN IP → Owning Org/Netblock:
For each selected host (IP) node, looks up ARIN for the owning organization and the parent netblock(s), attaching an organization node and the covering **CIDR node(s)** — the reverse of the org lookup, and a quick way to learn who an IP belongs to and expand to its whole allocation. Menu-triggered.

### DoxNS Lookup(x):
Proprietary database (not in the public repo).

### Reverse DoxNS Lookup(X):
Proprietary database (not in the public repo).

### IP DNS Query/Ping Sweep CIDR(i):
DNS lookup on the selected nodes. For a CIDR range, runs an ICMP ping sweep (equivalent to `nmap -sn -PE 192.168.0.0/24`). Ping sweeps require safety mode off.

### Mass IP DNS Query/Ping Sweep CIDR(I):
Like (i), against all subdomain and CIDR nodes. CIDR ranges are ping-swept only when safety mode is off.

### Subdomain Lookup (limit 100 queries/day)(s):
Subdomain search via AlienVault's and hackertarget.com's free APIs. Limited to 100 queries per day.

### CRT.SH Subdomain Lookup(S):
Subdomain search via crt.sh. Can surface internal domain names when an org reuses a certificate across internal and external hosts.

### Query Shodan (rate limit 1 per second)(q):
Shodan query on the selected node. One node at a time, due to Shodan's ~1 query/second limit.

### LinkedIn Search(l):
Mines LinkedIn for employee names and positions using a headless Chrome browser that mimics human scrolling. Set a current li_at cookie first, and select a node for results to attach to. Get the OrgID from a LinkedIn people-search URL — for `.../search/results/people/?facetCurrentCompany=11452158`, the OrgID is `11452158`; mine multiple OrgIDs one after another. **Do not thread or speed this module up** — it is intentionally slow to avoid account suspension.

### Email Search (limit 50 queries/month)(M):
Runs a Hunter.io and an SKS-KeyServer email search (free Hunter.io API key required). The free tier counts 10 emails as one query, up to 100 per query. Review the returned email sources — they often point to more emails and reveal other organizations the target works with.

### Flare Leaked Credentials(k):
Queries the [Flare](https://flare.io/) API for leaked credentials tied to the selected domain/network, subdomain, or email node. Results attach as credential nodes (`identity : secret`) and roll into the Emails and Credentials tallies. Requires a Flare API key (tenant id optional).

### Flare Breach Events(j):
Queries Flare for breach/threat events tied to the selected domain/network, subdomain, or email node. Results attach as breach-event nodes with metadata (source, date) readable via hover or the List View. Requires a Flare API key (tenant id optional).

### HTTP Probe + Screenshot(J):
Probes the selected web-reachable nodes (domain, subdomain, host, mail, name server) with a headless browser, turning a wall of hostnames into a triaged attack surface. For each live host it attaches a **web service** node with the HTTP status, page title, `Server`/`X-Powered-By` headers, resolved IP, a technology fingerprint (WordPress, Drupal, React, Angular, Vue, jQuery, `<meta generator>`), and a screenshot thumbnail (viewable in the List View detail pane). Probes run in one batch (max 150 hosts); dead hosts are skipped. The resolved IP is also added as a host node.

### Dork Generator(/):
From a selected domain, subdomain, or organization node, generates **dork** nodes — ready-to-run Google, GitHub, Wayback, and crt.sh searches for sensitive exposure (directory listings, documents, config/backup files, login/admin surfaces, secrets, redirect/SSRF params, employee enumeration, code/paste leaks). Open any with **View Website(v)**. No API keys required.

### Google Dork Search:
Runs a curated set of sensitive-exposure dorks against the selected domain/subdomain through the Google Programmable Search JSON API, attaching hits as web nodes (with title and snippet) under a dork node. Requires a Google CSE key and engine id (`cx`). Menu-triggered; the free tier allows ~100 queries/day.

### GitHub Code Dork Search:
Searches public GitHub code for the selected domain/organization to surface leaked hostnames, internal references, and secrets (env/config files, mentions near `password`/`secret`/`api_key`/`token`). Hits attach as info nodes labeled with the repo and file path. Requires a GitHub token (code search needs auth). Requests are spaced for the 10/minute limit, so a run takes ~30 seconds. Menu-triggered.

### Wayback URLs(K):
Pulls archived URLs for the selected domain/subdomain from the Internet Archive CDX API — forgotten endpoints, old admin panels, and parameterized routes. Results attach as **archived URL** nodes, and subdomains found along the way are added as subdomain nodes (so it doubles as a passive subdomain source). Prompts for a max URL count (default 500, max 5000).

### Subdomain Takeover Check(,):
Checks the selected domain/subdomain nodes for a **dangling CNAME** pointing at a de-provisioned SaaS/cloud resource that could be re-claimed. For each host it resolves the CNAME, fetches the live page, and matches a curated set of "unclaimed resource" fingerprints (GitHub Pages, S3, Heroku, Azure, Fastly, Shopify, Zendesk, Netlify, Read the Docs, and more). A match becomes a **Finding** node with the service, CNAME chain, and confidence — *high* when the CNAME and page signature agree, *medium* on a body signature alone. Healthy hosts emit nothing.

### Cloud Bucket Enumeration(.):
Derives a base keyword from the selected domain or organization node, generates name permutations (`-dev`, `-backup`, `-assets`, `-static`, `-uploads`, …), and probes **AWS S3**, **Google Cloud Storage**, and **Azure Blob**. Public buckets become **Finding** nodes; existing-but-private buckets and resolvable Azure accounts attach as info nodes. Open buckets carry their URL for **View Website(v)**. Makes a few dozen requests to the cloud providers (not the target's own infrastructure), bracketed by start/complete messages.

### Reverse IP / Shared Hosts(;):
For a selected host (IP) node, finds other domains served from the same IP (virtual hosts) via the hackertarget reverse-IP API. Results attach to the IP node as domain/subdomain nodes. The free API is rate limited.

### CVE Lookup:
Turns HTTP Probe fingerprints into vulnerability leads. For selected **web service** nodes, it parses product + version from their `Server`/`X-Powered-By`/`tech` metadata (e.g. `nginx/1.18.0`, `PHP/7.2.24`, `WordPress 6.1.1`), queries the [NVD](https://nvd.nist.gov/) API, and attaches the top CVEs by CVSS as **Potential CVE** nodes (score, severity, summary, NVD link via **View Website(v)**). Only versioned fingerprints are searched. Banners can be back-patched, so treat these as leads to verify. Works without a key (NVD throttles unauthenticated callers to ~5 requests/30s); an NVD API key makes it much faster. Menu-triggered.

### Generate Recon Report(📄) / Export Findings / Select All Findings:
**📄 Report** (toolbar or menu) builds a self-contained HTML report — summary counts, findings (takeovers, open buckets), potential CVEs, the web-service attack surface with embedded screenshots, leaked credentials, breach events, and an asset inventory — and downloads it from the browser. **Export Findings + CVEs (CSV)** writes just the actionable items. **Select All Findings + CVEs** selects every finding/CVE node (e.g. to feed the Engage `finding` export). Reports are generated client-side from the live graph.

### Location Search(L):
Finds the approximate lat/long for an IP. View location nodes in Google Maps with **View Website(v)**.

### DNS Zone Transfer(Z):
Runs an AXFR against all name servers for the selected domain/network nodes — noisy when it succeeds.

### Bruteforce Subdomains(b):
DNS subdomain brute force using the fuzzdb Alexa list. Fast on internal networks; good for finding hosts on internal assessments.

### Port Scan(p):
TCP port scan on the selected nodes (including CIDR ranges). Specify ports/ranges in the ports field, mixing both if you like (e.g. `21-25,80,443,8080`). Requires safety mode off.

### Mass Port Scan(P):
Like (p), against all IP nodes.
