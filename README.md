Scope Creep
=====
A mass target enumeration tool

Installation 
=====
This project is written in Node.js for its flexibility and non-blocking I/O.
You will need to install Node and NPM (Node Package Manager) to run the project: [Node.js Download](https://nodejs.org/en/download/)

Clone the repo and install the dependencies:
```
git clone https://github.com/fkasler/scope_creep.git
cd scope_creep
npm install
```

Getting Started
=====

- start the server and navigate to [http://localhost:3000](http://localhost:3000) in Chrome to get started:

```
node index.js
```

Session Persistence & Recovery
=====

Your recon graph used to live only in the browser tab, so a refresh (or a crash) wiped everything and you had to rebuild from scratch. Scope Creep now auto-saves your working graph as you go and lets you jump between past sessions.

- **Auto-save:** every change to the graph — adding nodes, running lookups, connecting, deleting, and any Flare metadata that lands on a node — is saved automatically in the background (debounced, so mass enumeration doesn't thrash). There's nothing to click.
- **Refresh recovery:** reload the tab (or reopen it later) and your last session is restored instantly — nodes, links, connections, labels, and Flare breach metadata all come back exactly as they were.
- **Session queue:** click the **⧉ Sessions** button in the top bar (or the "Sessions" row in the help menu) to open the queue. From there you can:
  - **＋ New Session** — start a fresh, empty graph (your current session is saved first).
  - **Switch** — click any session to load it back.
  - **✎ Rename** / **🗑 Delete** — manage your list.
- **Where it's stored:** the browser's `localStorage` is the live source of truth (that's what makes refresh recovery instant). Every save is also mirrored to a file under `sessions/` on the server as a durable backup. If you clear your browser data or open Scope Creep on another machine, those server backups show up in the queue tagged `backup` — click one to pull it back down. The `sessions/` directory is created automatically on server start and is git-ignored.

This is separate from **Export Graph (E)** / **Open Graph (O)**, which remain the way to save a named graph to a file you choose or share with someone else.

Usage/Modules
=====

- Scope Creep was built on Chrome. I hear the key bindings don't work on Firefox. You may experience issues with browsers other than Chrome. You've been warned.
- By default, "Safety" Mode is turned on to prevent the accidental running of mass queries against CIDR ranges and port scanning or ping sweeping anything. You can turn it off if you know what you're doing.
- You can trigger modules by clicking on them in the help menu. However, it's faster and more fun to learn the key bindings.
- You can select multiple nodes by either clicking on their row in the stats list or by using the node search.
- Node search/find(f) supports JavaScript regular expressions (e.g. 'domain.com' will select the domain and its subdomains but '^domain.com' will only select the domain and no subs). [regex reference](https://eloquentjavascript.net/09_regexp.html)
- Add values for [shodan](https://www.shodan.io/) api key, [whoxy](https://www.whoxy.com/reverse-whois/) api key, [li_at](https://www.linkedin.com/) cookie, [hunter.io](https://hunter.io/users/sign_up) api key, and [flare.io](https://flare.io/) api key to use those features. The value is saved in a cookie when you click out of the input so that they persist between page reloads.
- For automated dorking, add a [Google Programmable Search](https://developers.google.com/custom-search/v1/overview) API key **and** its search-engine id (`cx`), and a [GitHub personal access token](https://github.com/settings/tokens) (GitHub code search requires authentication). These are optional — the Dork Generator builds ready-to-run search links with no keys at all. Like the other credentials, they persist in cookies between reloads.
- The Flare tenant id field is optional. Leave it blank to use the default tenant on your Flare account, or set it to scope lookups to a specific tenant. Use the "Status" button next to the Flare key to confirm your key/tenant are valid.
- The toolbar has a few display toggles: switch between the force-directed graph and a tabular **List View**, flip the **theme** between dark and light (🌙/☀️), and cycle **node labels** between off, all, and selected-only (see below). These preferences persist in cookies between reloads.
- The li_at cookie is LinkedIn's session cookie and required to mine LinkedIn with Scope Creep. I recommend [editthiscookie](http://www.editthiscookie.com/) extension for Chrome to get your current session cookie.

### Add Node(a):
Press 'a' to select and clear the "Add Node(a)" input box. Hit enter to add the node to the graph.

### Help(h):
Toggles the help window in and out of the screen.

### Hide Stats(H):
Toggles the Stats list in and out of the screen.

### Toggle List View(z):
Switches between the force-directed graph and a tabular List View of the same data. The List View is handy when the graph gets too dense to read: it groups nodes by type, is searchable/sortable, and lets you jump back to a node in the graph ("Show in Graph"). You can also toggle it with the "List View" button in the toolbar.

### Toggle Theme(🌙/☀️):
The theme button in the toolbar flips the interface between dark and light. Your choice is saved in a cookie and restored on reload.

### Toggle Labels(🏷️):
Node labels are hidden by default and only appear when you hover a node (a selected node is always marked with a glowing icon). The "Labels" button in the toolbar cycles a persistent label mode across three states so you can read the graph without hovering every node:
- **Off** – default hover-only behavior.
- **All** – pin every node's label visible. Great on small graphs, but busy on large ones.
- **Selected** – pin labels for the currently selected nodes only. Select the handful of nodes you care about (via click, the stats list, or search) and read just those, without the clutter of everything else.

The chosen mode is saved in a cookie and restored on reload.

### Connect Nodes(c):
Select a node, hit 'c', and select another node to connect them. Press 'c' again to cancel if you accidentally hit it.

### Copy Nodes to Clipboard(y):
Yank the contents of the selected nodes to your clipboard. Useful for fast export of data like pulling an addresses.txt for phishing.

### Select First Connections(UP Arrow):
Adds every node directly connected to the current selection to the selection. Press it repeatedly to walk outward through the graph one hop at a time. Great for grabbing everything attached to a domain, host, or organization before running a mass operation.

### Export Nodes(e):
Export the contents of the selected nodes to a file name of your choosing. If you include the word 'finding' in the file name, the selected nodes will be exported in the format that Engage expects for finding imports. This is great for turning open port nodes into a finding like "Internet accessible authentication prompts".

### Export Graph(E):
Export the entire graph as a JSON object to a file. Useful for saving progress or sharing graphs with others.

### Select Nodes based on # of connections (0-9):
Select nodes based on how many nodes are connected to them. Good for some mass operations.

### Open Scope File(o):
Open a scope file with domains, subdomains, IPs, and CIDR ranges in it. This module needs you to select a parent node for the entries to attach to so they don't go flying in all directions. Supports wildcard imports (e.g. scope_file\* would import scope_file1.txt, scope_file2.txt, and scope_file_more_entries.txt)

### Open Graph(O):
Open a saved graph. This also supports wildcards. Wildcards are a great way to combine graphs into a single scope graph.

### Delete Nodes(d):
Deletes all selected nodes.

### Delete Unselected Nodes(D):
Deletes everything except the currently selected nodes. Great to use in combo with (f).

### Undo Deleted Nodes(u):
You can bring back connections to the selected nodes by using the undo feature. Useful for pairing down and building back graphs based on search criteria.

### Change Node Type(U):
Lets you update the node type for a single selected node.

### Whois Lookup(w):
Performs a Whois lookup on the selected IP node.

### Whoxy Reverse Whois Lookup(W):
Searches the Whoxy API for related domains based on Organization name, technical contact email, or keyword search. To search domain nodes like "example.com", use option (c) when prompted.

### MX Query(m):
Performs a DNS MX lookup on the selected nodes. Useful for quickly getting a list of mail servers.

### Reverse DNS Lookup(r):
Performs a DNS reverse lookup on the selected nodes. If a CIDR range is selected, it will do a reverse lookup for all possible IPs in the range. Great for quickly finding hosts on a network.

### Mass Reverse DNS Lookup(R):
Performs a DNS reverse lookup on ALL IP nodes in the graph.

### TXT Records(t):
Performs a DNS TXT lookup on the selected nodes. This module also tries to parse out CIDR ranges, hosts, and domains from SPF records.

### Mass TXT Records(T):
Same as (t), but against all domain nodes. This is great for enumerating runaway SPF records quickly.

### Name Servers(n):
Performs a DNS NS lookup on the selected nodes.

### Generate Emails(g):
Generates emails from all person nodes in the graph. If you leave the domain blank, it will not include the @ symbol so this is also good for generating usernames.

### Generate Phishmonger Target CSV(G):
Exports a CSV to the clipboard that contains a social engineering targets list. Useful in combination with the LinkedIn scraper and Hunter.io results.

### Convert IP Range to CIDR Node(C):
Takes a selected node that names an IP range (e.g. "192.168.0.0-192.168.0.255") and, when the range lines up exactly with a network boundary, spins off a matching CIDR node (e.g. "192.168.0.0/24"). Handy for turning range results into CIDR nodes you can then ping sweep or port scan.

### View Website in New Tab(v):
Opens a new Chrome tab for the selected nodes. Great for viewing web portals.

### Mass View Website in New Tab(V):
Opens a new Chrome tab for every subdomain node in the graph. Great for a quick look at subs to see what they're hosting.

### ASN search(A):
Searches for IP ranges that belong to an organization by querying the [http://asnlookup.com/](http://asnlookup.com/) API. The public repo only supports forward lookups based on organization name. I will link to resources on setting up a better API sometime in the future.

### DoxNS Lookup(x):
Proprietary DB for now. I will link to more details sometime in the future.

### Reverse DoxNS Lookup(X):
Proprietary DB for now. I will link to more details sometime in the future.

### IP DNS Query/Ping Sweep CIDR(i):
Performs a DNS lookup for the selected nodes. If a CIDR range is selected, this module performs an ICMP ping sweep on the range equivalent to 'nmap -sn -PE 192.168.0.0/24'. Ping sweeps are not allowed in safety mode.

### Mass IP DNS Query/Ping Sweep CIDR(I):
Performs a DNS lookup for ALL subdomain and CIDR nodes. CIDR is not scanned if safty mode is turned on. If a CIDR range is selected, this module performs an ICMP ping sweep on the range equivalent to 'nmap -sn -PE 192.168.0.0/24'

### Subdomain Lookup (limit 100 queries/day)(s):
Performs a subdomain search using alienvault's free API and hackertarget.com's free API. Limited to 100 queries per day. That's a lot of free data.

### CRT.SH Subdomain Lookup (unknown limit)(S):
Performs a subdomain search using crt.sh. This can find some cool stuff when it works. Sometimes you can even find internal domain names if the org uses the same cert for internal and external use.

### Query Shodan (rate limit 1 per second)(q):
Performs a Shodan query on the selected node. One node at a time limit because Shodan only allows a query per second or so and Node.js would try to do them all at once.

### LinkedIn Search (deactivation risk, DO NOT THREAD!)(l):
Mines LinkedIn for employee names and positions using a headless Chrome browser that mimics a human scrolling through pages. You need to make sure you have a current li_at cookie set first. You also need to select a node for the results to attach to. Go search for your target org in LinkedIn and get the OrgID and the number of results pages you want to mine. The OrgId for "https://www.linkedin.com/search/results/people/?facetCurrentCompany=11452158" would be 11452158. Sometimes you'll see multiple OrgIds. In those cases, just mine them one after the other. DO NOT TRY TO SPEED UP OR THREAD THIS MODULE!!!!!!!!! YOU CAN GET BUSTED AND ACCOUNT SUSPENDED!!!! It is slow for a reason.

### Email Search (limit 50 queries/month)(M):
Performs a Hunter.io email search and a SKS-KeyServer email search. Go get a free Hunter.io account and grab the api key. The free API allows a limited number of results per month but 10 emails is equal to one result. The max emails per query is 100 so that will burn 10 "queries" if you get 100 results. I recommend exporting and looking through the email sources that it returns. They can point to directories and places to get other emails. They can also give you an idea of other organizations that your target works with. Great for blackbox testing.

### Flare Leaked Credentials(k):
Queries the [Flare](https://flare.io/) API for leaked credentials tied to the selected domain/network, subdomain, or email nodes. Results come back as credential nodes (parent : secret) attached to the node you searched, and roll up into the Emails and Credentials tallies in the stats panel. Requires a Flare api key in the settings panel (the tenant id is optional).

### Flare Breach Events(j):
Queries the Flare API for breach/threat events associated with the selected domain/network, subdomain, or email nodes. Results attach as breach event nodes with friendly labels and metadata (source, date, etc.) that you can read via hover or the List View. Requires a Flare api key in the settings panel (the tenant id is optional).

### HTTP Probe + Screenshot(J):
Visits the selected web-reachable nodes (domain, subdomain, host, mail, or name server) with a headless browser and turns a wall of hostnames into a triaged attack surface. For each host it tries `https://` then `http://` and, on a live response, attaches a **web service** node carrying the HTTP status, page title, `Server`/`X-Powered-By` headers, resolved IP, a best-effort technology fingerprint (WordPress, Drupal, React, Angular, Vue, jQuery, `<meta generator>`, …), and a **screenshot thumbnail**. Read the metadata and view the screenshot in the List View detail pane (or hover the node for the text summary). Select as many nodes as you like — they're probed in one batch by a single browser instance (capped at 150 hosts per run). Dead hosts are skipped silently. The resolved IP is also spun off as a host node so it folds into the rest of your graph.

### Dork Generator(/):
From a selected domain, subdomain, or organization node, spins off a set of ready-to-run **dork** nodes — each one a Google, GitHub, Wayback, or crt.sh search URL tuned for sensitive exposure (directory listings, documents, config/backup files, login/admin surfaces, secrets in indexed pages, redirect/SSRF params, employee enumeration, and code/paste leaks). Open any of them in a new tab with **View Website(v)**. This needs no API keys and works instantly — it's the fast, always-available OSINT layer.

### Google Dork Search:
Runs a curated set of sensitive-exposure dorks (documents, config/backups, directory listings, auth surfaces, secrets in pages) against the selected domain/subdomain through the Google Programmable Search JSON API and attaches the hits as web nodes under a dork node, each with the result title and snippet. Requires a Google CSE api key and search-engine id (`cx`) in the settings panel. Menu-triggered (no key binding) to keep it deliberate — the free tier is limited to ~100 queries/day.

### GitHub Code Dork Search:
Searches public GitHub code for the selected domain/organization to surface leaked hostnames, internal references, and secrets (env files, config files, and mentions near `password`/`secret`/`api_key`/`token`). Hits attach as info nodes labeled with the repo and file path. GitHub's code search API **requires authentication**, so set a GitHub token in the settings panel. Requests are spaced out to respect the 10-requests/minute limit, so a run takes ~30 seconds. Menu-triggered.

### Wayback URLs(K):
Pulls archived URLs for the selected domain/subdomain from the Internet Archive's CDX API — a great way to surface forgotten endpoints, old admin panels, and parameterized routes that no longer appear in normal crawling. Results attach as **archived URL** nodes, and any subdomains discovered along the way are added as subdomain nodes too (so Wayback doubles as a passive subdomain source). You'll be prompted for a max number of URLs to pull (default 500, capped at 5000) to keep the graph manageable.

### Subdomain Takeover Check(,):
Checks the selected domain/subdomain nodes for a **dangling CNAME** — a subdomain still pointing at a de-provisioned SaaS/cloud resource that an attacker (or you, in an assessment) could re-claim. For each host it resolves the CNAME, fetches the live page, and matches the response against a curated set of "unclaimed resource" fingerprints (GitHub Pages, S3, Heroku, Azure, Fastly, Shopify, Zendesk, Netlify, Read the Docs, and more). A match becomes a **Finding** node flagged `⚠ Takeover?` with the service, the CNAME chain, and a confidence rating — *high* when the CNAME and the page signature both point at the same service, *medium* on a body signature alone. Nothing is emitted for healthy hosts, so a clean run leaves the graph untouched.

### Cloud Bucket Enumeration(.):
Derives a base keyword from the selected domain or organization node, generates name permutations (`-dev`, `-backup`, `-assets`, `-static`, `-uploads`, …), and probes **AWS S3**, **Google Cloud Storage**, and **Azure Blob** for each. Publicly listable buckets become **Finding** nodes (`⚠ Public S3/GCS bucket`); buckets that exist but are private, and Azure storage accounts that resolve, attach as info nodes so you know they're there. Open buckets carry the URL, so **View Website(v)** opens them straight away. This fires a few dozen requests to the cloud providers (not to the client's own infrastructure) and takes a little while — a start and a completion message bracket the run.

### Reverse IP / Shared Hosts(;):
Given a selected host (IP) node, finds other domains served from the same IP — virtual hosts sharing the box — via the hackertarget reverse-IP API. Discovered hostnames attach to the IP node as domain/subdomain nodes, expanding scope on shared hosting. The free API is rate limited, so use it deliberately; if you burn the quota the tool tells you.

### Location Search (general rate limit)(L):
Tries to find the Lat/Long location associated with an IP. You can view location nodes in Google maps by using the "View Website in New Tab(v)" module.

### DNS Zone Transfer(Z):
Performs a Zone Transfer against the selected domain/network nodes. This will run a axfr query against ALL name servers for the domain so it can be noisy if successful.

### Bruteforce Subdomains (interacts with client servers)(b):
Performs DNS subdomain bruteforcing using the alexa list from fuzzdb. This can take a while but generally goes fast on private networks. Great for quickly finding hosts with DNS on internal assessments/SE.

### Port Scan/Port Scan ALL IPs(p):
Performs a TCP port scan on the selected nodes. Supports individual CIDR ranges. You specify the ports/ranges in the ports input field. You can mix ports and ranges if you'd like (e.g. 21-15,80,443,8080,4444-555). Not allowed in safety mode.

### Mass Port Scan/Port Scan ALL IPs(P):
Performs a TCP port scan on ALL IP nodes. You specify the ports/ranges in the ports input field. You can mix ports and ranges if you'd like (e.g. 21-15,80,443,8080,4444-555). Not allowed in safety mode.
