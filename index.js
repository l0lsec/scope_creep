fs = require('fs');
glob = require("glob").glob
dateFormat = require('dateformat');
var app = require('express')();
var http = require('http').Server(app);
http_resolver = require('http')
https_resolver = require('https')
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
var io = require('socket.io')(http);
var dns = require('dns');
var axfr = require('dns-axfr');
//CIDR parser
netmask = require('netmask').Netmask
//headless chrome stuff
const puppeteer = require('puppeteer');
//port scanner
evilscan = require('evilscan');
//ping sweeps
var ping = require('ping');
var path = require('path');

// ---------------------------------------------------------------------------
// Session persistence: durable, file-based mirror of the browser's live
// recon session. The browser (localStorage) is the source of truth for
// instant refresh recovery; these files are the backup that survives a
// browser-cache clear or lets you pick a session up on another machine.
// ---------------------------------------------------------------------------
var SESSIONS_DIR = path.join(__dirname, 'sessions');
try {
  fs.mkdirSync(SESSIONS_DIR, { recursive: true });
} catch (err) {
  console.log('could not create sessions directory: ' + err);
}

// Session ids come from the browser and are used to build file paths, so
// keep them to a safe, traversal-proof character set before touching disk.
function safe_session_id(id) {
  if (typeof id !== 'string') { return null; }
  var cleaned = id.replace(/[^A-Za-z0-9_-]/g, '');
  if (cleaned === '' || cleaned.length > 128) { return null; }
  return cleaned;
}

function session_file(id) {
  var safe = safe_session_id(id);
  if (!safe) { return null; }
  return path.join(SESSIONS_DIR, safe + '.json');
}

app.get('/', function(req, res){
  res.sendFile(__dirname + '/scopecreep.html');
});

app.get('/favicon.ico', function(req, res){
  res.sendFile(__dirname + '/images/favicon.ico');
});

app.get('/scripts/jquery.min.js', function(req, res){
  res.sendFile(__dirname + '/scripts/jquery.min.js');
});

app.get('/scripts/jquery.cookie.js', function(req, res){
  res.sendFile(__dirname + '/scripts/jquery.cookie.js');
});

app.get('/scripts/vivagraph.min.js', function(req, res){
  res.sendFile(__dirname + '/scripts/vivagraph.min.js');
});

app.get('/scripts/socket.io.js', function(req, res){
  res.sendFile(__dirname + '/scripts/socket.io.js');
});

app.get('/images/network', function(req, res){
  res.sendFile(__dirname + '/images/network.svg');
});

app.get('/images/mail', function(req, res){
  res.sendFile(__dirname + '/images/mail.svg');
});

app.get('/images/server', function(req, res){
  res.sendFile(__dirname + '/images/server.svg');
});

app.get('/images/subdomain', function(req, res){
  res.sendFile(__dirname + '/images/subdomain.svg');
});

app.get('/images/txt', function(req, res){
  res.sendFile(__dirname + '/images/txt.svg');
});

app.get('/images/organization', function(req, res){
  res.sendFile(__dirname + '/images/organization.svg');
});

app.get('/images/cidr', function(req, res){
  res.sendFile(__dirname + '/images/cidr.svg');
});

app.get('/images/person', function(req, res){
  res.sendFile(__dirname + '/images/person.svg');
});

app.get('/images/linkedin', function(req, res){
  res.sendFile(__dirname + '/images/linkedin.svg');
});

app.get('/images/position', function(req, res){
  res.sendFile(__dirname + '/images/position.svg');
});

app.get('/images/nameserver', function(req, res){
  res.sendFile(__dirname + '/images/nameserver.svg');
});

app.get('/images/port', function(req, res){
  res.sendFile(__dirname + '/images/port.svg');
});

app.get('/images/email', function(req, res){
  res.sendFile(__dirname + '/images/email.svg');
});

app.get('/images/info', function(req, res){
  res.sendFile(__dirname + '/images/info.svg');
});

app.get('/images/location', function(req, res){
  res.sendFile(__dirname + '/images/location.svg');
});

app.get('/images/phone', function(req, res){
  res.sendFile(__dirname + '/images/phone.svg');
});

app.get('/images/credential', function(req, res){
  res.sendFile(__dirname + '/images/credential.svg');
});

app.get('/images/event', function(req, res){
  res.sendFile(__dirname + '/images/event.svg');
});

app.get('/images/web', function(req, res){
  res.sendFile(__dirname + '/images/web.svg');
});

app.get('/images/dork', function(req, res){
  res.sendFile(__dirname + '/images/dork.svg');
});

app.get('/images/url', function(req, res){
  res.sendFile(__dirname + '/images/url.svg');
});

app.get('/images/vuln', function(req, res){
  res.sendFile(__dirname + '/images/vuln.svg');
});

// ---------- Flare API client (ported from flare-lookup-cli) ----------
// Talks to https://api.flare.io: exchange an API key for a short-lived Bearer
// token, then POST the global credentials/events search endpoints and follow
// the `next` cursor. Node building is done with object literals by the callers
// (breach data is full of quotes/$/%/backslashes that break string-built JSON).
var FLARE_HOST = 'api.flare.io';
var FLARE_CRED_PAGE_SIZE = 1000;   // API max is 10000; big pages -> fewer round-trips
var FLARE_EVENT_PAGE_SIZE = 10;    // API max for events
var flareTokenCache = {};          // apiKey -> { token, ts }

// Low-level POST to api.flare.io. cb(err, statusCode, parsedJsonOrNull).
function flarePost(path, headers, body, cb){
  var payload = body ? JSON.stringify(body) : '';
  var finished = false;
  function done(err, status, parsed){ if(finished){ return; } finished = true; cb(err, status, parsed); }
  var options = {
    host: FLARE_HOST,
    path: path,
    method: 'POST',
    headers: Object.assign({ 'Content-Length': Buffer.byteLength(payload) }, headers)
  };
  var req = https_resolver.request(options, function(res){
    var data = '';
    res.on('data', function(chunk){ data += chunk; });
    res.on('end', function(){
      var parsed = null;
      try { parsed = data ? JSON.parse(data) : null; } catch(e) { parsed = null; }
      done(null, res.statusCode, parsed);
    });
  });
  req.on('error', function(err){ done(err); });
  req.setTimeout(60000, function(){ req.destroy(new Error('Flare request timeout')); });
  if(payload){ req.write(payload); }
  req.end();
}

// Exchange the API key for a short-lived token, optionally scoped to a tenant.
// The token is tenant-scoped, so the cache is keyed by apiKey+tenant. cb(err, token).
function flareToken(apiKey, tenant, cb){
  if(!apiKey){ cb('no API key set (settings panel or FLARE_API_KEY env)'); return; }
  var cacheKey = apiKey + '|' + (tenant || '');
  var cached = flareTokenCache[cacheKey];
  if(cached && (Date.now() - cached.ts) < 50 * 60 * 1000){ cb(null, cached.token); return; }
  var path = '/tokens/generate' + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
  flarePost(path, { 'Authorization': apiKey }, null, function(err, status, parsed){
    if(err){ cb('token request failed: ' + err.message); return; }
    if(status !== 200 || !parsed || !parsed.token){ cb('token generation failed (HTTP ' + status + ')'); return; }
    flareTokenCache[cacheKey] = { token: parsed.token, ts: Date.now() };
    cb(null, parsed.token);
  });
}

// One search page with 429 exponential backoff (2/4/8s, 4 attempts). cb(err, items, next).
function flareSearchPage(path, token, body, attempt, cb){
  flarePost(path, { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, body, function(err, status, parsed){
    if(err){ cb(err); return; }
    if(status === 429){
      if(attempt >= 3){ cb(new Error('429 Too Many Requests after retries')); return; }
      setTimeout(function(){ flareSearchPage(path, token, body, attempt + 1, cb); }, Math.pow(2, attempt + 1) * 1000);
      return;
    }
    if(status !== 200){ cb(new Error('search HTTP ' + status)); return; }
    cb(null, (parsed && parsed.items) || [], parsed && parsed.next);
  });
}

// Follow the `next` cursor (maxPages falsy = all pages), 1s between pages. onItems(items) per page.
function flarePaginate(path, token, buildBody, maxPages, onItems){
  var page = 0;
  function nextPage(from){
    if(maxPages && page >= maxPages){ return; }
    page++;
    flareSearchPage(path, token, buildBody(from), 0, function(err, items, next){
      if(err){ io.emit('server_message', 'Flare: ' + err.message); return; }
      onItems(items);
      if(next && (!maxPages || page < maxPages)){ setTimeout(function(){ nextPage(next); }, 1000); }
    });
  }
  nextPage(null);
}

// Map a selected graph node to a Flare query object (email vs domain/fqdn).
function flareQueryForNode(nodeId, nodeType){
  if(nodeType === 'email'){ return { type: 'email', email: nodeId }; }
  return { type: 'domain', fqdn: nodeId }; // network / subdomain
}

// Flatten a Flare record into a compact { key: value } map for the UI. Keeps
// top-level scalars plus one level into nested objects, and drops noise / huge /
// secret-duplicating fields. Bounded in field count and value length so a fat
// stealer-log record can't bloat the graph payload. Schema-agnostic on purpose:
// whatever fields a record actually carries get passed through.
function flareMeta(rec){
  var meta = {};
  var SKIP = { hash: 1, password: 1, passwords: 1, cookies: 1, cookie: 1, _score: 1,
               score: 1, id: 1, uid: 1, banner: 1, raw: 1, html: 1, screenshot: 1 };
  var count = 0;
  function add(key, val){
    if(count >= 24 || val === null || val === undefined){ return; }
    if(typeof val === 'boolean'){ val = val ? 'yes' : 'no'; }
    var s = String(val).trim();
    if(s === '' || s === '[object Object]'){ return; }
    if(s.length > 300){ s = s.slice(0, 300) + '…'; }
    if(meta[key] === undefined){ meta[key] = s; count++; }
  }
  Object.keys(rec || {}).forEach(function(k){
    if(SKIP[k]){ return; }
    var v = rec[k];
    if(Array.isArray(v)){
      add(k, v.filter(function(x){ return x && typeof x !== 'object'; }).join(', '));
    } else if(v && typeof v === 'object'){
      Object.keys(v).forEach(function(k2){
        if(!SKIP[k2] && v[k2] && typeof v[k2] !== 'object'){ add(k + '.' + k2, v[k2]); }
      });
    } else {
      add(k, v);
    }
  });
  return meta;
}

// Best-effort human label for a breach event (its uid is opaque). Returns null
// when none of the expected fields are present, so callers fall back to the uid.
// Flare's global events carry the type in `index`, the date in
// `metadata.estimated_created_at`, and the source in `metadata.source`; credential-
// style records use top-level fields. Both shapes are handled.
function flareEventLabel(ev){
  ev = ev || {};
  var md = ev.metadata || {};
  var src = ev.source || md.source;
  var srcName = (src && typeof src === 'object') ? src.name : src;
  var type = ev.type || ev.index || md.type;
  var name = ev.name || srcName || ev.title || ev.actor;
  var date = ev.created_at || md.estimated_created_at || ev.timestamp || md.first_crawled_at || ev.imported_at || ev.leaked_at;
  if(date){ date = String(date).slice(0, 10); }
  var parts = [type, name, date].filter(Boolean).map(function(s){ return String(s).trim(); }).filter(Boolean);
  return parts.length ? parts.join(' · ') : null;
}

// Best-effort "breach source" string, promoted to a shared info node so events /
// credentials from the same source can be grouped and selected together. Returns
// null when nothing source-like is present. Credential records expose `source` as
// an object ({name, leaked_at, ...}); events nest it under `metadata.source`.
function flareSource(rec){
  rec = rec || {};
  var md = rec.metadata || {};
  var s = rec.source || md.source;
  if(s && typeof s === 'object'){ s = s.name || s.id; }
  s = s || rec.actor || md.actor || rec.source_id || rec.breach || null;
  if(!s){ return null; }
  s = String(s).trim();
  return s ? s.slice(0, 120) : null;
}

io.on('connection', function(socket){
  socket.on('whois_lookup', function(query){
    var whois = require('whois')
    whois.lookup(query, function(err, data) {
      var searches = [
        {"search_string": "CIDR:", "node_type": "cidr"},
        {"search_string": "NetRange:", "node_type": "info"},
        {"search_string": "Organization:", "node_type": "organization"},
        {"search_string": "OrgTechEmail:", "node_type": "email"},
        {"search_string": "OrgName:", "node_type": "organization"}
      ]
      for(i=0; i < searches.length; i++){
        myRegexp = new RegExp(`^${searches[i].search_string}.+$`,"gm");
        do {
          match = myRegexp.exec(data);
          if (match) {
            new_node = JSON.parse('{"id": "'+ match[0].replace(/ /g,'').split(':')[1] + '", "parent": "' + query + '", "node_type": "' + searches[i].node_type +'"}')
            io.emit('add_node', new_node)
          }
        } while (match);
      }
    })
  });

  socket.on('whoxy_api_check', function(query_object){

    api_call = 'https://api.whoxy.com/?key=' + query_object + '&account=balance'

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        try{
          results = JSON.parse(data)
          io.emit('server_message', "Available Balance: " + results.reverse_whois_balance)
        }catch (err){
          io.emit('server_message', "There is a problem with your API key")
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('whoxy_search', function(query_object){

    if(query_object.search_method == 'email'){
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&email=' + query_object.node_id + '&page=' + query_object.page_number
    }else if(query_object.search_method == 'keyword'){
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&keyword=' + query_object.node_id + '&page=' + query_object.page_number
    }else{
      api_call = 'https://api.whoxy.com/?key=' + query_object.whoxy_api_key + '&reverse=whois&company=' + query_object.node_id + '&page=' + query_object.page_number
    }

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        if(results.total_pages > 1){
          io.emit('server_message', "Total Pages: " + results.total_pages)
        }
        for(i=0; i < results.search_result.length; i++){
          record = results.search_result[i]
          new_node = JSON.parse('{"id": "'+ record.domain_name + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
          io.emit('add_node', new_node)
          if(record.registrant_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.administrative_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.technical_contact.company_name){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.company_name + '", "parent": "' + record.domain_name  + '", "node_type": "organization"}')
            io.emit('add_node', new_node)
          }
          if(record.registrant_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.registrant_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.registrant_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.registrant_contact.phone_number + '", "parent": "' + record.registrant_contact.email_address + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
          if(record.administrative_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.administrative_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.administrative_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.administrative_contact.phone_number + '", "parent": "' + record.administrative_contact.email_address + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
          if(record.technical_contact.email_address){
            new_node = JSON.parse('{"id": "'+ record.technical_contact.email_address + '", "parent": "' + record.domain_name  + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            if(record.technical_contact.phone_number){
              new_node = JSON.parse('{"id": "'+ record.technical_contact.phone_number + '", "parent": "' + record.technical_contact.email_address  + '", "node_type": "phone"}')
              io.emit('add_node', new_node)
            }
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });


  socket.on('mx_query', function(query){
    dns.resolveMx(query, function(err, addresses){
      for (server in addresses){
        new_node = JSON.parse('{"id": "'+ addresses[server].exchange + '", "parent": "' + query + '", "node_type": "mail"}')
        io.emit('add_node', new_node)
      }
    })
  });

  socket.on('reverse_lookup', function(query_object){
    //run a reverse lookup on everything in the range if it's a CIDR subnet
    if(query_object.node_type == "cidr"){
       var block = new netmask(query_object.node_id);
       block.forEach(function(ip){
         dns.reverse(ip.toString(), function(err, addresses){
          for (server in addresses){
            if(addresses[server].split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
            }
            io.emit('add_node', new_node)
          }
        })
      });
    //otherwise treat like a single query
    }else if(query_object.node_type == "port"){
      let host = query_object.node_id.split(':')[0]
      let port = query_object.node_id.split(':')[1]
      let options = {
        host: host,
        port: port,
        method: 'GET'
      }
      try{
        let req = https_resolver.request(options, function(res) {
          let host_names = res.connection.getPeerCertificate().subjectaltname.replace(/DNS:/g,'').split(',')
          host_names.forEach(function(host_name){
            if(host_name.trim().split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ host_name.trim() + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ host_name.trim() + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
            }
            io.emit('add_node', new_node)
          })
        })
        req.end()
      }catch(err){
        //no cert names
      }
    }else{
      dns.reverse(query_object.node_id, function(err, addresses){
        for (server in addresses){
          if(addresses[server].split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
        }
      })
      let host = query_object.node_id
      let options = {
        host: host,
        port: 443,
        method: 'GET'
      }
      try{
        let req = https_resolver.request(options, function(res) {
          let host_names = res.connection.getPeerCertificate().subjectaltname.replace(/DNS:/g,'').split(',')
          host_names.forEach(function(host_name){
            if(host_name.trim().split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ host_name.trim() + '", "parent": "' + query_object.node_id + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ host_name.trim() + '", "parent": "' + query_object.node_id + '", "node_type": "subdomain"}')
            }
            io.emit('add_node', new_node)
          })
        })
        req.end()
      }catch(err){
        //no cert names
      }
    }
  });

  socket.on('txt_records', function(query){
    dns.resolveTxt(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry][0] + '", "parent": "' + query + '", "node_type": "txt"}')
        io.emit('add_node', new_node)
        if(records[entry][0].indexOf('v=spf') !== -1){
          myRegexp = /ip4:(\d+\.\d+\.\d+\.\d+([^\s]+))/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              if(match[1].indexOf('/') !== -1){
                new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "cidr"}')
              }else if(match[1].indexOf('-') !== -1){
                new_node = JSON.parse('{"id": "Net Range: '+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "info"}')
              }else{
                new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "server"}')
              }
              io.emit('add_node', new_node)
            }
          } while (match);
          myRegexp = /include:([^\s]+)/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
          } while (match);
          myRegexp = /a:([^\s]+)/g
          do {
            match = myRegexp.exec(records[entry]);
            if (match) {
              new_node = JSON.parse('{"id": "'+ match[1] + '", "parent": "' + records[entry][0] + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            }
          } while (match);
        }
      }
    })
  });

  socket.on('nameservers', function(query){
    dns.resolveNs(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry] + '", "parent": "' + query + '", "node_type": "nameserver"}')
        io.emit('add_node', new_node)
      }
    })
  });

  socket.on('ip_lookup', function(query_object){
    //run a ping sweep if this is a CIDR range
    if(query_object.node_type == "cidr"){
      var block = new netmask(query_object.node_id);
      block.forEach(function(host){
        ping.sys.probe(host, function(isAlive){
            if(isAlive){
              new_node = JSON.parse('{"id": "'+ host + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            }
        });

      });
    }else{
      dns.resolve(query_object.node_id.toString(), function(err, addresses){
        for (server in addresses){
          new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
          io.emit('add_node', new_node)
        }
      })
    }
  });

  socket.on('export_graph', function(query_object){
    if(query_object.file_name == ""){
      query_object.file_name = "export"
    }
    if(query_object.export_type == 'list'){
      fs.writeFile("./" + query_object.file_name, query_object.export_list, function(err) {
        if(err) {
          console.log(err);
        }
        io.emit('server_message', "File Exported: ./" + query_object.file_name)
      });
    }else{
      fs.writeFile("./" + query_object.file_name + "_" + dateFormat(new Date(), "yyyy-mm-dd_HH-MM-ss")+".js", JSON.stringify(query_object.graph_object,false, 2), function(err) {
        if(err) {
          console.log(err);
        }
        io.emit('server_message', "File Exported: ./" + query_object.file_name + "_" +dateFormat(new Date(), "yyyy-mm-dd_HH-MM-ss")+".js")
      });
    }
  });

  socket.on('subdomain_lookup', function(query){
    https_resolver.get('https://api.hackertarget.com/hostsearch/?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        if(resp.statusCode != 200){
          console.log("hackertarget hostsearch returned status " + resp.statusCode + " for " + query)
          return
        }
        lower_query = query.toLowerCase()
        lines = data.split('\n')
        for(line in lines){
          subdomain = lines[line].split(',')
          subdomain_name = (subdomain[0] || '').trim().toLowerCase()
          subdomain_ip = (subdomain[1] || '').trim()
          // Only accept real hosts belonging to the queried domain (drops HTML/error bodies)
          if(subdomain_name != lower_query && !subdomain_name.endsWith('.' + lower_query)){ continue }
          node_type = subdomain_name.split('.').length == 2 ? "network" : "subdomain"
          io.emit('add_node', {id: subdomain_name, parent: query, node_type: node_type})
          if(/^(\d{1,3}\.){3}\d{1,3}$/.test(subdomain_ip)){
            io.emit('add_node', {id: subdomain_ip, parent: subdomain_name, node_type: "server"})
          }
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

    https_resolver.get('https://otx.alienvault.com/api/v1/indicators/domain/' + query + '/passive_dns',  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        var results
        try {
          results = JSON.parse(data).passive_dns
        } catch(err) {
          console.log("Error parsing AlienVault OTX response: " + err.message)
          return
        }
        if(!Array.isArray(results)){ return }
        lower_query = query.toLowerCase()
        for(i=0;i<results.length;i++){
          if(!results[i].hostname){ continue }
          hostname = results[i].hostname.trim().toLowerCase()
          if(hostname != lower_query && !hostname.endsWith('.' + lower_query)){ continue }
          io.emit('add_node', {id: hostname, parent: query, node_type: "subdomain"})
          if(results[i].address){
            io.emit('add_node', {id: results[i].address, parent: hostname, node_type: "server"})
          }
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  // Validate a Flare API key (settings "Status" button): try a token exchange.
  socket.on('flare_api_check', function(query_object){
    var apiKey = (query_object && query_object.flare_api_key) || process.env.FLARE_API_KEY;
    var tenant = (query_object && query_object.flare_tenant) || process.env.FLARE_TENANT;
    flareToken(apiKey, tenant, function(err, token){
      if(err){ io.emit('server_message', 'Flare: ' + err); return; }
      io.emit('server_message', 'Flare API key OK (token acquired)');
    });
  });

  // Flare leaked-credential lookup: domain/email node -> leaked emails + passwords.
  socket.on('flare_credentials', function(query_object){
    var apiKey = (query_object && query_object.flare_api_key) || process.env.FLARE_API_KEY;
    var tenant = (query_object && query_object.flare_tenant) || process.env.FLARE_TENANT;
    var nodeId = query_object.node_id;
    var nodeType = query_object.node_type;
    if(['network','subdomain','email'].indexOf(nodeType) === -1){
      io.emit('server_message', 'Flare lookup: select a domain or email node');
      return;
    }
    var q = flareQueryForNode(nodeId, nodeType);
    var lowerDomain = (nodeType === 'email') ? null : String(nodeId).toLowerCase();
    flareToken(apiKey, tenant, function(err, token){
      if(err){ io.emit('server_message', 'Flare credentials: ' + err); return; }
      flarePaginate('/firework/v4/credentials/global/_search', token,
        function(from){
          var b = { query: q, size: FLARE_CRED_PAGE_SIZE, order: 'desc' };
          if(from){ b.from = from; }
          return b;
        },
        null, // no cap: page through every result
        function(items){
          for(var i = 0; i < items.length; i++){
            var c = items[i] || {};
            var identity = (c.identity_name || '').trim();
            if(!identity || identity.indexOf('@') === -1){ continue; }
            // For a domain search, keep only identities that belong to the domain (drops noise).
            if(lowerDomain){
              var recDomain = (c.domain || '').toLowerCase();
              if(identity.toLowerCase().indexOf('@' + lowerDomain) === -1 && recDomain !== lowerDomain){ continue; }
            }
            var emailParent;
            if(nodeType === 'email'){
              emailParent = nodeId; // credentials hang off the already-selected email node
            } else {
              io.emit('add_node', { id: identity, parent: nodeId, node_type: 'email' });
              emailParent = identity;
            }
            var secret = (c.hash || '').trim();
            if(secret){
              // Scope the credential id to its identity so a password reused across two
              // accounts stays under each owner instead of merging onto one shared node.
              var credId = emailParent + ' : ' + secret;
              io.emit('add_node', { id: credId, parent: emailParent, node_type: 'credential', meta: flareMeta(c) });
              // Promote the breach source to a shared info node so every credential from
              // the same leak groups under it (selectable/groupable in graph + list).
              var credSource = flareSource(c);
              if(credSource){
                io.emit('add_node', { id: 'source: ' + credSource, parent: credId, node_type: 'info' });
              }
            }
          }
        }
      );
    });
  });

  // Flare threat-event lookup: domain/email node -> breach/stealer-log/paste events.
  socket.on('flare_events', function(query_object){
    var apiKey = (query_object && query_object.flare_api_key) || process.env.FLARE_API_KEY;
    var tenant = (query_object && query_object.flare_tenant) || process.env.FLARE_TENANT;
    var nodeId = query_object.node_id;
    var nodeType = query_object.node_type;
    if(['network','subdomain','email'].indexOf(nodeType) === -1){
      io.emit('server_message', 'Flare lookup: select a domain or email node');
      return;
    }
    var q = flareQueryForNode(nodeId, nodeType);
    flareToken(apiKey, tenant, function(err, token){
      if(err){ io.emit('server_message', 'Flare events: ' + err); return; }
      flarePaginate('/firework/v4/events/global/_search', token,
        function(from){
          var b = { query: q, size: FLARE_EVENT_PAGE_SIZE, order: 'desc' };
          if(from){ b.from = from; }
          return b;
        },
        null, // no cap: page through every result
        function(items){
          for(var i = 0; i < items.length; i++){
            var ev = items[i] || {};
            if(!ev.uid){ continue; }
            // Keep the id = uid (guaranteed unique) but ship a human-readable label
            // and the full metadata so the node isn't an opaque UID in either view.
            io.emit('add_node', { id: ev.uid, parent: nodeId, node_type: 'event',
                                  label: flareEventLabel(ev), meta: flareMeta(ev) });
            var evSource = flareSource(ev);
            if(evSource){
              io.emit('add_node', { id: 'source: ' + evSource, parent: ev.uid, node_type: 'info' });
            }
          }
        }
      );
    });
  });

  socket.on('asn_search', function(query_object){
    var api_call = 'http://asnlookup.com/api/lookup?org=' + encodeURIComponent(query_object.node_id)
//    if(query_object.node_type == "server"){
//      api_call = 'http://10.0.50.105:10120/ip_to_asn?q=' + query_object.node_id
//    }else if(query_object.node_type == "info"){
//      api_call = 'http://10.0.50.105:10120/asn_to_org?q=' + query_object.node_id.replace(/ASN:/,'')
//    }else{
//      api_call = 'http://10.0.50.105:10120/org_to_asn?q=' + query_object.node_id
//    }
    http_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
//          new_node = JSON.parse('{"id": "'+ results[result].org + '", "parent": "' + query_object.node_id + '", "node_type": "organization"}')
//          io.emit('add_node', new_node)
//          new_node = JSON.parse('{"id": "ASN:'+ results[result].asn + '", "parent": "' + results[result].org + '", "node_type": "info"}')
//          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "' + results[result] + '", "parent": "' + query_object.node_id + '", "node_type": "cidr"}')
          io.emit('add_node', new_node)
//          new_node = JSON.parse('{"id": "Country:'+ results[result].country + '", "parent": "' + results[result].org + '", "node_type": "info"}')
//          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('dox_ns', function(query){
    http_resolver.get('http://10.0.50.105:10120/search?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
          subdomain_name = results[result].name
          subdomain_ip = results[result].value
          if(subdomain_name.split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
          
          if(results[result].type == 'cname'){
            if(subdomain_name.split('.').length == 2){
              new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "network"}')
            }else{
              new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "subdomain"}')
            }
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_ip + '", "parent": "' + subdomain_name + '", "node_type": "server"}')
          }
          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('reverse_dox_ns', function(query){
    http_resolver.get('http://10.0.50.105:10120/reverse_search?q=' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        for(result in results){
          subdomain_name = results[result].name
          subdomain_ip = results[result].value
          if(subdomain_name.split('.').length == 2){
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "network"}')
          }else{
            new_node = JSON.parse('{"id": "'+ subdomain_name + '", "parent": "' + query + '", "node_type": "subdomain"}')
          }
          io.emit('add_node', new_node)
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('crtsh_lookup', function(query){
    https_resolver.get('https://crt.sh/?q=%25.' + query,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        myRegexp = new RegExp(`<TD>([^>\ =]+\.${query})`, 'g')
        do {
          match = myRegexp.exec(data);
          if (match) {
            subdomain_name = match[1].toLowerCase().trim()
            if(!subdomain_name){ continue }
            node_type = subdomain_name.split('.').length > 2 ? "subdomain" : "network"
            io.emit('add_node', {id: subdomain_name, parent: query, node_type: node_type})
          }
        } while (match);
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('bruteforce_subdomains', function(query){
    //console.log(dateFormat("isoDateTime") + " starting bruteforce");
    dns.resolve('notavalidsubdomain.' + query, function(err, wildcardIP){
      if(wildcardIP){
        new_node = JSON.parse('{"id": "*.' + query + '", "parent": "' + query + '", "node_type": "subdomain"}')
        io.emit('add_node', new_node)
        new_node = JSON.parse('{"id": "'+ wildcardIP[0] + '", "parent": "*.' + query + '", "node_type": "server"}')
        io.emit('add_node', new_node)
      }else{
        wildcardIP = ['1.1.1.1']
      }
      var lineReader = require('readline').createInterface({
        //input: fs.createReadStream('./lists/servers.txt')
        input: fs.createReadStream('./lists/alexaTop1mAXFRcommonSubdomains.txt')
      });
      lineReader.on('line', function (subdomain) {
        dns.resolve(subdomain + '.' + query, function(err, addresses){
          if (typeof(addresses) !== 'undefined'){
            if(addresses[0] !== wildcardIP[0]){
              new_node = JSON.parse('{"id": "'+ subdomain + '.' + query + '", "parent": "' + query + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
              for (server in addresses){
                new_node = JSON.parse('{"id": "'+ addresses[server] + '", "parent": "' + subdomain + '.' + query + '", "node_type": "server"}')
                io.emit('add_node', new_node)
              }
            }
          }
        })
      })
    })
    lineReader.on('close', function () {
      //console.log(dateFormat("isoDateTime") + " finished bruteforce");
    });
  });

  socket.on('port_scan', function(query_object){
    //console.log(dateFormat("isoDateTime") + " starting port scan");
    if(query_object.node_type == 'cidr'){
       var block = new netmask(query_object.node_id);
       target_range = block.first + "-" + block.last
    }else{
      target_range = query_object.node_id
    }
    let options = {
        target : target_range,
        // target  :'192.168.1.1-5',
        // target  :'192.168.1.1-192.168.1.5',
        //port    :'21, 22, 23, 25, 80, 443, 4443, 4444, 3389, 139, 137, 8443, 8080',
        port    : query_object.port_list,
        //status  : 'TROU', // Timeout, Refused, Open, Unreachable
        status  : 'O', // Timeout, Refused, Open, Unreachable
        timeout : 3000,
        banner  : false,//maybe we can collect this later. Might slow down the scans though
        //geo	    : true
    };

    let scanner = new evilscan(options);
    scanner.on('result',function (data) {
    	// fired when item is matching options
    	//console.log(data);
        //make sure to create ip nodes if we are scanning a range
        if(query_object.node_type == 'cidr'){
          new_node = JSON.parse('{"id": "'+ data.ip + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "'+ data.ip + ':' + data.port + '", "parent": "' + data.ip + '", "node_type": "port"}')
          io.emit('add_node', new_node)
        }else{
          new_node = JSON.parse('{"id": "'+ data.ip + ':' + data.port + '", "parent": "' + query_object.node_id + '", "node_type": "port"}')
          io.emit('add_node', new_node)
        }
    });
    scanner.on('error',function (err) {
    	//throw new Error(data.toString());
    	console.log(data.toString());
    });
    scanner.on('done',function () {
      //console.log(dateFormat("isoDateTime") + " finished port scan");
    });
    scanner.run();
  });

  socket.on('location_search', function(query_object){
    api_call = {
      hostname: 'ipapi.co',
      path: '/' + query_object + '/json/',
      headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' }
    };
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        location_results = JSON.parse(data)
        try{
          new_node = JSON.parse('{"id": "'+ location_results.latitude + ':' + location_results.longitude + '", "parent": "' + query_object + '", "node_type": "location"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "State: '+ location_results.region + '", "parent": "' + query_object + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "City: '+ location_results.city + '", "parent": "' + query_object + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
        try{
          new_node = JSON.parse('{"id": "'+ location_results.org + '", "parent": "' + query_object + '", "node_type": "organization"}')
          io.emit('add_node', new_node)
        }catch (err){
        }
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

  });

  socket.on('convert_to_cidr', function(query_object){
    try{
      query_object = query_object.replace(/[\s\n\r]+/g,'')
      range = query_object.split('-')
      base_ip = range[0]
      limit_ip = range[1]
      for(mask = 32; mask > 0; mask -= 1){
        var block = new netmask(base_ip + "/" + mask.toString());
        if((block.base == base_ip)&(block.broadcast == limit_ip)){
          new_node = JSON.parse('{"id": "'+ base_ip + "/" + mask.toString() + '", "parent": "' + query_object + '", "node_type": "cidr"}')
          io.emit('add_node', new_node)
          //console.log(block)
        }
      }
    }catch (err){
      io.emit('server_message', "Error Converting to CIDR: " + err)
    }
  });

  socket.on('zone_transfer', function(query){
    dns.resolveNs(query, function(err, records){
      for (entry in records){
        new_node = JSON.parse('{"id": "'+ records[entry] + '", "parent": "' + query + '", "node_type": "nameserver"}')
        io.emit('add_node', new_node)
        axfr.resolveAxfrTimeout(1000);
        axfr.resolveAxfr(records[entry], query, function(err, addr) {
          if (err) {
            //console.error('Error ocurred: ' + addr + ' (' + err + ')');
            return;
          }
          results = addr.answers
          for(i=0;i<results.length;i++){
            if(results[i].name.slice(-1) == '.'){
              results[i].name = results[i].name.slice(0, -1)
            }
            new_node = JSON.parse('{"id": "'+ results[i].name + '", "parent": "' + query + '", "node_type": "subdomain"}')
            io.emit('add_node', new_node)
            if(results[i].dns){
              new_node = JSON.parse('{"id": "'+ results[i].dns.slice(0, -1) + '", "parent": "' + results[i].name + '", "node_type": "nameserver"}')
              io.emit('add_node', new_node)
            }
            if(results[i].mail){
              new_node = JSON.parse('{"id": "'+ results[i].mail.slice(0, -1) + '", "parent": "' + results[i].name + '", "node_type": "mail"}')
              io.emit('add_node', new_node)
            }
            if(results[i].a){
              new_node = JSON.parse('{"id": "'+ results[i].a + '", "parent": "' + results[i].name + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            }
          }
        })
      }
    })
  });

  socket.on('hunter_api_check', function(query_object){

    api_call = 'https://api.hunter.io/v2/account?api_key=' + query_object

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        try{
          results = JSON.parse(data)
          io.emit('server_message', "Used: " + results.data.calls.used + "\nAvailable: " + (results.data.calls.available - results.data.calls.used) + "\nResets: " + results.data.reset_date)
        }catch (err){
          io.emit('server_message', "There is a problem with your API key")
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });


  socket.on('email_search', function(query_object){

    api_call = 'https://sks-keyservers.net/pks/lookup?search=' + query_object.node_id 
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        myRegexp = />([^<]+@[^<]+)/g
        do {
          match = myRegexp.exec(data);
          if (match) {
            name = match[1].slice(0, match[1].indexOf('&lt;'))
            email = match[1].slice(match[1].indexOf('&lt;')+4, match[1].indexOf('&gt;'))
            new_node = JSON.parse('{"id": "'+ email + '", "parent": "' + query_object.node_id + '", "node_type": "email"}')
            io.emit('add_node', new_node)
            new_node = JSON.parse('{"id": "'+ name + '", "parent": "' + email + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }
        } while (match);
      });

    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });

    api_call = 'https://api.hunter.io/v2/domain-search?limit=1000&domain=' + query_object.node_id + '&api_key=' + query_object.hunter_api_key

    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        results = JSON.parse(data)
        if(results.data.pattern){
          new_node = JSON.parse('{"id": "Mail Pattern:'+ results.data.pattern + '", "parent": "' + query_object.node_id + '", "node_type": "info"}')
          io.emit('add_node', new_node)
        }
        if(results.data.organization){
          new_node = JSON.parse('{"id": "'+ results.data.organization + '", "parent": "' + query_object.node_id + '", "node_type": "organization"}')
          io.emit('add_node', new_node)
        }
        for(i=0; i < results.data.emails.length; i++){
          email = results.data.emails[i]
          new_node = JSON.parse('{"id": "'+ email.value + '", "parent": "' + query_object.node_id + '", "node_type": "email"}')
          io.emit('add_node', new_node)
          if(email.first_name && email.last_name){
            new_node = JSON.parse('{"id": "'+ email.first_name + ' ' + email.last_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }else if(email.first_name){
            new_node = JSON.parse('{"id": "'+ email.first_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }else if(email.last_name){
            new_node = JSON.parse('{"id": "'+ email.last_name + '", "parent": "' + email.value + '", "node_type": "person"}')
            io.emit('add_node', new_node)
          }
          if(email.position){
            new_node = JSON.parse('{"id": "'+ email.position + '", "parent": "' + email.value + '", "node_type": "position"}')
            io.emit('add_node', new_node)
          }
          if(email.twitter){
            new_node = JSON.parse('{"id": "www.twitter.com/'+ email.twitter + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
          if(email.linkedin){
            new_node = JSON.parse('{"id": "www.linkedin.com/in/'+ email.linkedin + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
          if(email.phone_number){
            new_node = JSON.parse('{"id": "'+ email.phone_number + '", "parent": "' + email.value + '", "node_type": "phone"}')
            io.emit('add_node', new_node)
          }
          for(j=0; j < email.sources.length; j++){
            source = email.sources[j]
            new_node = JSON.parse('{"id": "Email Source:'+ source.uri + '", "parent": "' + email.value + '", "node_type": "info"}')
            io.emit('add_node', new_node)
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('query_shodan', function(query_object){
    if(query_object.node_type == "organization"){
      api_call = 'https://api.shodan.io/shodan/host/search?query=org:"' + encodeURIComponent(query_object.node_id) + '"&key=' + query_object.api_key
    }else if((query_object.node_type == "cidr") || (query_object.node_type == "server")) {
      api_call = 'https://api.shodan.io/shodan/host/search?query=net:' + encodeURIComponent(query_object.node_id) + '&key=' + query_object.api_key
    }else{
      api_call = 'https://api.shodan.io/shodan/host/search?query=hostname:' + encodeURIComponent(query_object.node_id) + '&key=' + query_object.api_key
    }
    https_resolver.get(api_call,  (resp) => {
      let data = '';

      resp.on('data', (chunk) => {
        data += chunk;
      });

      resp.on('end', () => {
        shodan_results = JSON.parse(data)
        for(i=0; i < shodan_results.matches.length; i++) {
          match = shodan_results.matches[i]
          try {
            server = match.ip_str
            new_node = JSON.parse('{"id": "'+ server + '", "parent": "' + query_object.node_id + '", "node_type": "server"}')
            io.emit('add_node', new_node)
            host_names = match.hostnames
            for (j=0; j < host_names.length; j++) {
              subdomain = host_names[j]
              new_node = JSON.parse('{"id": "'+ subdomain + '", "parent": "' + server + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            }
            network_names = match.domains
            for (j=0; j < network_names.length; j++) {
              network = host_names[j]
              new_node = JSON.parse('{"id": "'+ network + '", "parent": "' + server + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
            if(match.port){
              new_node = JSON.parse('{"id": "'+ server + ":" + match.port + '", "parent": "' + server + '", "node_type": "port"}')
              io.emit('add_node', new_node)
            }
            if(match.location.longitude){
              new_node = JSON.parse('{"id": "'+ match.location.latitude + ":" + match.location.longitude + '", "parent": "' + server + '", "node_type": "location"}')
              io.emit('add_node', new_node)
              if(match.location.city){
                new_node = JSON.parse('{"id": "City: '+ match.location.city + '", "parent": "' + match.location.latitude + ":" + match.location.longitude + '", "node_type": "info"}')
                io.emit('add_node', new_node)
              }
              if(match.location.region_code){
                new_node = JSON.parse('{"id": "State: '+ match.location.region_code + '", "parent": "' + match.location.latitude + ":" + match.location.longitude + '", "node_type": "info"}')
                io.emit('add_node', new_node)
              }
            }
            if(match.org){
              new_node = JSON.parse('{"id": "'+ match.org + '", "parent": "' + server + '", "node_type": "organization"}')
              io.emit('add_node', new_node)
            }
          } catch (err) {
            console.log(err);
          }
        }
      });
    }).on("error", (err) => {
       console.log("Error: " + err.message);
    });
  });

  socket.on('linkedin_search', function(query_object){
    linkedinMiner(query_object.node_id, io, query_object.linkedin_cookie, query_object.org_id, query_object.start_page, query_object.end_page)
  });

  socket.on('open_file', function(query_object){
    glob(query_object.file_path).then(function (files) {
      for (var i=0; i<files.length; i++) {
        io.emit('server_message', "Importing File: " + files[i])
        fs.readFile(files[i], function(err,scope_file){
          file_lines = scope_file.toString().split('\n')
          for(i=0; i<file_lines.length; i++){
            if(file_lines[i].indexOf('/') !== -1){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "cidr"}')
              io.emit('add_node', new_node)
            } else if(file_lines[i].split('.').length == 4){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "server"}')
              io.emit('add_node', new_node)
            } else if(file_lines[i].split('.').length == 3){
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "subdomain"}')
              io.emit('add_node', new_node)
            } else {
              new_node = JSON.parse('{"id": "'+ file_lines[i] + '", "parent": "' + query_object.parent_node + '", "node_type": "network"}')
              io.emit('add_node', new_node)
            }
          }
        });
      }
    })
  });

  socket.on('open_graph', function(graph_path){
    //check if we need to import any graphs
    glob(graph_path).then(function (files) {
      for (var i=0; i<files.length; i++) {
        io.emit('server_message', "Importing Graph: " + files[i])
        fs.readFile(files[i], function(err,graph_file){
          graph_import = JSON.parse(graph_file);
          for(i=0; i<graph_import.nodes.length; i++){
            io.emit('import_node', graph_import.nodes[i])
          }
          for(i=0; i<graph_import.links.length; i++){
            io.emit('import_link', graph_import.links[i])
          }
        });
      }
    })
  });

  // --- Session persistence handlers ----------------------------------------
  // Mirror the browser's auto-saved session to disk so it survives a cache
  // clear. Fired continuously (debounced client-side), so this stays quiet.
  socket.on('save_session', function(session){
    if(!session || typeof session !== 'object'){ return }
    var file = session_file(session.id);
    if(!file){ return }
    fs.writeFile(file, JSON.stringify(session), function(err){
      if(err){ console.log('save_session failed: ' + err) }
    });
  });

  // List every backed-up session (lightweight summaries) so the browser can
  // surface server-only sessions in the queue after localStorage is wiped.
  socket.on('list_sessions', function(){
    fs.readdir(SESSIONS_DIR, function(err, files){
      if(err){ socket.emit('sessions_list', []); return }
      var summaries = [];
      var pending = files.filter(function(f){ return f.slice(-5) === '.json' });
      if(pending.length === 0){ socket.emit('sessions_list', []); return }
      var remaining = pending.length;
      pending.forEach(function(f){
        fs.readFile(path.join(SESSIONS_DIR, f), function(rerr, data){
          if(!rerr){
            try {
              var s = JSON.parse(data);
              summaries.push({
                id: s.id,
                name: s.name,
                createdAt: s.createdAt,
                updatedAt: s.updatedAt,
                nodeCount: (s.nodes || []).length
              });
            } catch(pe){ /* skip corrupt file */ }
          }
          remaining -= 1;
          if(remaining === 0){ socket.emit('sessions_list', summaries) }
        });
      });
    });
  });

  // Send back a full session for the browser to restore (used when the
  // session exists on the server but not in this browser's localStorage).
  socket.on('load_session', function(query){
    var id = query && query.id;
    var file = session_file(id);
    if(!file){ return }
    fs.readFile(file, function(err, data){
      if(err){ socket.emit('server_message', 'Could not load session: ' + id); return }
      try {
        socket.emit('session_data', JSON.parse(data));
      } catch(pe){
        socket.emit('server_message', 'Session file was corrupt: ' + id);
      }
    });
  });

  // Remove a backed-up session file when the user deletes it from the queue.
  socket.on('delete_session', function(query){
    var id = query && query.id;
    var file = session_file(id);
    if(!file){ return }
    fs.unlink(file, function(err){
      if(err && err.code !== 'ENOENT'){ console.log('delete_session failed: ' + err) }
    });
  });

  // HTTP probe + screenshot: visit the selected hosts with a headless browser and
  // report status/title/tech/server + a thumbnail so a wall of subdomains can be
  // triaged as a real attack surface. Runs one browser for the whole batch.
  socket.on('http_probe', function(query_object){
    httpProbe(query_object, io);
  });

  // Wayback URLs: pull archived endpoints for a domain from the archive.org CDX
  // API. Surfaces forgotten paths/params and doubles as a subdomain source.
  socket.on('wayback_urls', function(query_object){
    var domain = query_object && query_object.node_id;
    if(!domain){ return; }
    var limit = parseInt(query_object.limit, 10);
    if(!limit || limit < 1){ limit = 500; }
    if(limit > 5000){ limit = 5000; }
    var api = 'http://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain) +
              '&matchType=domain&fl=original&collapse=urlkey&output=json&limit=' + limit;
    http_resolver.get(api, function(resp){
      var data = '';
      resp.on('data', function(chunk){ data += chunk; });
      resp.on('end', function(){
        var rows;
        try { rows = JSON.parse(data); } catch(e){ io.emit('server_message', 'Wayback: could not parse response'); return; }
        if(!Array.isArray(rows) || rows.length < 2){ io.emit('server_message', 'Wayback: no archived URLs for ' + domain); return; }
        var seenUrl = {}, seenHost = {}, count = 0;
        for(var i = 1; i < rows.length; i++){
          var original = Array.isArray(rows[i]) ? rows[i][0] : rows[i];
          if(!original || seenUrl[original]){ continue; }
          seenUrl[original] = 1;
          var host = '';
          try { host = new URL(original).hostname.toLowerCase(); } catch(e){ host = ''; }
          var parent = domain;
          if(host && host !== domain && host.slice(-(domain.length + 1)) === '.' + domain){
            if(!seenHost[host]){
              seenHost[host] = 1;
              io.emit('add_node', { id: host, parent: domain, node_type: 'subdomain' });
            }
            parent = host;
          }
          io.emit('add_node', { id: original, parent: parent, node_type: 'url' });
          count++;
        }
        io.emit('server_message', 'Wayback: added ' + count + ' archived URLs for ' + domain);
      });
    }).on('error', function(err){ io.emit('server_message', 'Wayback error: ' + err.message); });
  });

  // Google dork search: run a set of sensitive-exposure dorks through the Google
  // Programmable Search JSON API. Results attach as web nodes under a dork node.
  socket.on('dork_google', function(query_object){
    var target = query_object && query_object.node_id;
    var key = query_object && query_object.google_key;
    var cx = query_object && query_object.google_cx;
    if(!target){ return; }
    if(!key || !cx){ io.emit('server_message', 'Google dork: set a Google CSE key and cx in settings'); return; }
    var dorks = googleDorkList(target);
    var idx = 0;
    function runNext(){
      if(idx >= dorks.length){ return; }
      var d = dorks[idx++];
      var api = 'https://www.googleapis.com/customsearch/v1?key=' + encodeURIComponent(key) +
                '&cx=' + encodeURIComponent(cx) + '&num=10&q=' + encodeURIComponent(d.q);
      https_resolver.get(api, function(resp){
        var data = '';
        resp.on('data', function(chunk){ data += chunk; });
        resp.on('end', function(){
          var r;
          try { r = JSON.parse(data); } catch(e){ setTimeout(runNext, 400); return; }
          if(r && r.error){ io.emit('server_message', 'Google dork: ' + (r.error.message || 'API error')); return; }
          var items = (r && r.items) || [];
          if(items.length){
            var dorkId = 'google: ' + d.label + ' (' + target + ')';
            io.emit('add_node', { id: dorkId, parent: target, node_type: 'dork', meta: { query: d.q, results: String(items.length) } });
            items.forEach(function(it){
              io.emit('add_node', { id: it.link, parent: dorkId, node_type: 'web',
                label: (it.title || it.link).slice(0, 80),
                meta: { title: (it.title || '').slice(0, 200), snippet: (it.snippet || '').slice(0, 300), dork: d.label } });
            });
          }
          setTimeout(runNext, 400);
        });
      }).on('error', function(){ setTimeout(runNext, 400); });
    }
    runNext();
  });

  // GitHub code dork search: hunt public repos for leaked hostnames/secrets tied
  // to the target. Code search requires an authenticated token. Hits attach as
  // info nodes under a dork node. Spaced out to respect the 10 req/min limit.
  socket.on('dork_github', function(query_object){
    var target = query_object && query_object.node_id;
    var token = query_object && query_object.github_token;
    if(!target){ return; }
    if(!token){ io.emit('server_message', 'GitHub dork: set a GitHub token in settings (code search requires auth)'); return; }
    var dorks = githubDorkList(target);
    var idx = 0;
    function runNext(){
      if(idx >= dorks.length){ return; }
      var d = dorks[idx++];
      var options = {
        host: 'api.github.com',
        path: '/search/code?per_page=10&q=' + encodeURIComponent(d.q),
        method: 'GET',
        headers: { 'Authorization': 'token ' + token, 'User-Agent': 'scope_creep', 'Accept': 'application/vnd.github.v3+json' }
      };
      var req = https_resolver.request(options, function(resp){
        var data = '';
        resp.on('data', function(chunk){ data += chunk; });
        resp.on('end', function(){
          var r;
          try { r = JSON.parse(data); } catch(e){ setTimeout(runNext, 7000); return; }
          if(r && r.message && !r.items){ io.emit('server_message', 'GitHub dork: ' + r.message); return; }
          var items = (r && r.items) || [];
          if(items.length){
            var dorkId = 'github: ' + d.label + ' (' + target + ')';
            io.emit('add_node', { id: dorkId, parent: target, node_type: 'dork', meta: { query: d.q, results: String(r.total_count || items.length) } });
            items.forEach(function(it){
              var repo = it.repository ? it.repository.full_name : '';
              io.emit('add_node', { id: it.html_url, parent: dorkId, node_type: 'info',
                label: (repo + ' — ' + (it.path || '')).slice(0, 90),
                meta: { repo: repo, path: it.path || '', url: it.html_url } });
            });
          }
          setTimeout(runNext, 7000);
        });
      });
      req.on('error', function(){ setTimeout(runNext, 7000); });
      req.end();
    }
    runNext();
  });

  // Subdomain takeover check: resolve each selected host's CNAME, fetch the live
  // page, and flag it when the response carries the "unclaimed resource" signature
  // of a known SaaS/cloud provider (a dangling CNAME you may be able to claim).
  socket.on('subdomain_takeover', function(query_object){
    var hosts = (query_object && query_object.hosts) || [];
    if(!hosts.length){ return; }
    io.emit('server_message', 'Takeover check started on ' + hosts.length + ' host(s)...');
    var pending = hosts.length, hits = 0;
    function oneDone(hit){
      if(hit){ hits++; }
      if(--pending <= 0){ io.emit('server_message', 'Takeover check complete: ' + hits + ' potential issue(s) found'); }
    }
    hosts.forEach(function(host){
      dns.resolveCname(host, function(err, cnames){
        checkTakeover(host, cnames || [], io, oneDone);
      });
    });
  });

  // Cloud bucket enumeration: derive a base keyword from the selected domain/org,
  // generate name permutations, and probe AWS S3, Google GCS, and Azure Blob.
  // Public/listable buckets become findings; existing-but-private ones become info.
  socket.on('cloud_buckets', function(query_object){
    var seed = query_object && query_object.node_id;
    if(!seed){ return; }
    var names = bucketCandidates(seed);
    io.emit('server_message', 'Cloud bucket scan started (' + names.length + ' candidate names)...');
    var idx = 0, found = 0;
    function next(){
      if(idx >= names.length){
        io.emit('server_message', 'Cloud bucket scan complete: ' + found + ' bucket(s)/account(s) found');
        return;
      }
      var name = names[idx++];
      checkBucket(name, seed, io, function(hit){ if(hit){ found++; } setTimeout(next, 120); });
    }
    next();
  });

  // Reverse IP / shared-host discovery: find other domains served from the same IP
  // (virtual hosts) via the hackertarget reverse-IP API. Great for shared hosting.
  socket.on('reverse_ip', function(query_object){
    var ip = query_object && query_object.node_id;
    if(!ip){ return; }
    https_resolver.get('https://api.hackertarget.com/reverseiplookup/?q=' + encodeURIComponent(ip), function(resp){
      var data = '';
      resp.on('data', function(chunk){ data += chunk; });
      resp.on('end', function(){
        if(!data || /error|API count exceeded|no records/i.test(data)){
          io.emit('server_message', 'Reverse IP: ' + (data ? data.split('\n')[0] : 'no data') + ' (' + ip + ')');
          return;
        }
        var lines = data.split('\n'), count = 0;
        lines.forEach(function(h){
          h = h.trim().toLowerCase();
          if(!h){ return; }
          var nt = h.split('.').length > 2 ? 'subdomain' : 'network';
          io.emit('add_node', { id: h, parent: ip, node_type: nt });
          count++;
        });
        io.emit('server_message', 'Reverse IP: ' + count + ' host(s) sharing ' + ip);
      });
    }).on('error', function(err){ io.emit('server_message', 'Reverse IP error: ' + err.message); });
  });

});

http.listen(3000, function(){
  //console.log('listening on *:3000');
  console.log('listening on *:3000');
});

//catch any server exceptions instead of exiting
http.on('error', function (e) {
  console.log(dateFormat("isoDateTime") + " " + e);
});

//catch any node exceptions instead of exiting
process.on('uncaughtException', function (err) {
  console.log(dateFormat("isoDateTime") + " " + 'Caught exception: ', err);
});

function wait (timeout) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, (timeout + Math.random()*1000))
  })
}

//sorry this function is so funky! had to do some sync gynastics to keep enumeration to a human level so we don't get busted ;D
async function linkedinMiner(parent_node, io, linkedin_cookie, org_id, start_page, end_page) {
  let puppet_options = ["--ignore-certificate-errors", "--disable-blink-features=AutomationControlled"]

  let browser = await puppeteer.launch({
    headless: true,
    acceptInsecureCerts: true,
    ignoreDefaultArgs: ["--enable-automation"],
    defaultViewport: null,
    args: puppet_options
  })

  var page = await browser.newPage()

  await page.setCookie({
    'value': linkedin_cookie,
    'domain': 'www.linkedin.com',
    'expires': Date.now() / 1000 + 10000,
    'name': 'li_at'
  });
 
  async function getPage(page_number){
    return new Promise(async function(resolve, reject){
      await page.goto('https://www.linkedin.com/search/results/people/?currentCompany=%5B%22' + org_id + '%22%5D&page=' + page_number)
  
      await wait(2000)
      let script1 = "window.scrollTo(0,(document.body.scrollHeight/2));"
      await page.evaluate(script1)
      await wait(2000)
      let script2 = "window.scrollTo(0,document.body.scrollHeight);"
      await page.evaluate(script2)
      await wait(2000)
//    let script3 = 'names = document.getElementsByClassName("name actor-name");output = "";for (i = 0; i < names.length; i++){ if (names[i].text != "LinkedIn Member"){output = output + "\\n" + (names[i].innerHTML)}};output;'
//      let script3 = 'names = document.getElementsByClassName("name actor-name");output = "";for (i = 0; i < names.length; i++){ if (names[i].text != "LinkedIn Member"){output = output + "\\n" + (names[i].innerHTML + ":" + names[i].parentNode.parentNode.parentNode.parentNode.parentNode.getElementsByTagName("p")[0].textContent.trim())}};output;'
      let script3 = 'people = document.getElementsByClassName("entity-result");output = "";for (i = 0; i < people.length; i++){let name; try{name = people[i].getElementsByClassName("entity-result__title-text  t-16")[0].getElementsByTagName("a")[0].children[0].children[0].innerText}catch(err){continue};if(name != "LinkedIn Member"){position = people[i].getElementsByClassName("entity-result__primary-subtitle t-14 t-black")[0].innerText;output = output + `\\n${name}:${position}`;}};output;'
      result = await page.evaluate(script3)
      //console.log(result)
      resolve(result)
    })
  }

  for (i=start_page;i<=end_page;i++) {
    results = await getPage(i).catch( e => { } )
    employees = results.split('\n')
    //console.log(employees);
    for(j=0; j<employees.length;j++){
      employee = employees[j]
      if(employee !== ''){
        try{
          new_node = JSON.parse('{"id": "' + org_id + ' page ' + i + '", "parent": "' + parent_node + '", "node_type": "linkedin"}')
          io.emit('add_node', new_node)
          name_position = employee.split(':')
          new_node = JSON.parse('{"id": "' + name_position[0] + '", "parent": "' + org_id + ' page ' + i + '", "node_type": "person"}')
          io.emit('add_node', new_node)
          new_node = JSON.parse('{"id": "' + name_position[1] + '", "parent": "' + name_position[0] + '", "node_type": "position"}')
          io.emit('add_node', new_node)
        }catch (err){
          console.log(name_position)
        }
      }
    }
  }

  browser.close();

}

// Sensitive-exposure dorks for the Google Programmable Search API. Kept tight and
// high-signal: documents, configs/backups, directory listings, auth surfaces, and
// secrets leaking into indexed pages.
function googleDorkList(target){
  var s = 'site:' + target + ' ';
  return [
    { label: 'Documents',          q: s + '(filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)' },
    { label: 'Config & backups',   q: s + '(ext:env OR ext:ini OR ext:conf OR ext:cfg OR ext:yml OR ext:bak OR ext:old OR ext:sql OR ext:log)' },
    { label: 'Directory listings', q: s + 'intitle:"index of"' },
    { label: 'Login & admin',      q: s + '(inurl:admin OR inurl:login OR intitle:login OR inurl:portal)' },
    { label: 'Secrets in pages',   q: s + '("api_key" OR "apikey" OR "authorization: bearer" OR "BEGIN RSA PRIVATE KEY" OR "aws_secret")' }
  ];
}

// GitHub code-search dorks for leaked hostnames/secrets tied to the target domain.
function githubDorkList(domain){
  return [
    { label: 'Domain mentions', q: '"' + domain + '"' },
    { label: 'Secrets near host', q: '"' + domain + '" (password OR secret OR api_key OR token)' },
    { label: 'Env files', q: '"' + domain + '" filename:.env' },
    { label: 'Config files', q: '"' + domain + '" (filename:config OR extension:yml OR extension:conf)' }
  ];
}

// Best-effort client-side technology fingerprint from the loaded page.
async function sniffTech(page){
  try {
    return await page.evaluate(function(){
      var t = [];
      var g = document.querySelector('meta[name="generator"]');
      if(g && g.content){ t.push(g.content); }
      if(window.wp || document.querySelector('link[href*="wp-content"],script[src*="wp-content"]')){ t.push('WordPress'); }
      if(window.Drupal){ t.push('Drupal'); }
      if(window.Joomla){ t.push('Joomla'); }
      if(window.Shopify){ t.push('Shopify'); }
      if(window.React || document.querySelector('[data-reactroot],#__next')){ t.push('React'); }
      if(window.angular || document.querySelector('[ng-version]')){ t.push('Angular'); }
      if(document.querySelector('[data-v-app]') || window.__VUE__){ t.push('Vue'); }
      if(window.jQuery){ t.push('jQuery'); }
      return t.filter(function(v, i){ return t.indexOf(v) === i; }).slice(0, 6).join(', ');
    });
  } catch(e){ return ''; }
}

// Visit one host (https first, then http), collect status/title/tech/server + a
// small screenshot thumbnail, and emit a 'web' node under the probed host node.
async function probeOne(browser, target, io){
  var schemes = /^https?:\/\//i.test(target) ? [target] : ['https://' + target, 'http://' + target];
  var page;
  try { page = await browser.newPage(); } catch(e){ return; }
  try {
    var resp = null;
    for(var s = 0; s < schemes.length; s++){
      try {
        resp = await page.goto(schemes[s], { waitUntil: 'domcontentloaded', timeout: 15000 });
        if(resp){ break; }
      } catch(e){ resp = null; }
    }
    if(!resp){ return; }                       // dead / unreachable host, skip quietly
    var status = resp.status();
    var finalUrl = page.url();
    var title = '';
    try { title = await page.title(); } catch(e){}
    var headers = resp.headers() || {};
    var ipStr = '';
    try { ipStr = (resp.remoteAddress && resp.remoteAddress.ip) || ''; } catch(e){}
    var tech = await sniffTech(page);
    var shot = '';
    try {
      var buf = await page.screenshot({ type: 'jpeg', quality: 45 });
      shot = 'data:image/jpeg;base64,' + buf.toString('base64');
    } catch(e){}
    var meta = { url: finalUrl, status: String(status) };
    if(headers['server']){ meta.server = String(headers['server']).slice(0, 120); }
    if(headers['x-powered-by']){ meta['x-powered-by'] = String(headers['x-powered-by']).slice(0, 120); }
    if(ipStr){ meta.ip = ipStr; }
    if(tech){ meta.tech = tech; }
    if(title){ meta.title = String(title).slice(0, 200); }
    if(shot){ meta.screenshot = shot; }
    var label = status + (title ? ' · ' + String(title).slice(0, 60) : '');
    io.emit('add_node', { id: finalUrl, parent: target, node_type: 'web', label: label, meta: meta });
    if(ipStr){ io.emit('add_node', { id: ipStr, parent: finalUrl, node_type: 'server' }); }
  } catch(e){
    console.log('http_probe error on ' + target + ': ' + e.message);
  } finally {
    try { await page.close(); } catch(e){}
  }
}

// Probe a batch of hosts with a single headless browser instance.
async function httpProbe(query_object, io){
  var targets = (query_object && query_object.targets) || [];
  var MAX_TARGETS = 150;
  if(targets.length > MAX_TARGETS){
    io.emit('server_message', 'HTTP probe capped at ' + MAX_TARGETS + ' hosts (selected ' + targets.length + ')');
    targets = targets.slice(0, MAX_TARGETS);
  }
  if(!targets.length){ return; }
  var puppet_options = ['--ignore-certificate-errors', '--disable-blink-features=AutomationControlled', '--no-sandbox'];
  var browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      acceptInsecureCerts: true,
      ignoreDefaultArgs: ['--enable-automation'],
      defaultViewport: { width: 1024, height: 640 },
      args: puppet_options
    });
  } catch(e){ io.emit('server_message', 'HTTP probe: could not launch browser: ' + e.message); return; }
  for(var i = 0; i < targets.length; i++){
    var target = String(targets[i]).trim();
    if(!target){ continue; }
    await probeOne(browser, target, io);
  }
  try { await browser.close(); } catch(e){}
  io.emit('server_message', 'HTTP probe complete (' + targets.length + ' hosts)');
}

// Simple GET that returns the (size-capped) response body. cb(err, status, body, headers).
// Does not follow redirects on purpose -- we want to inspect the direct response.
function httpGetBody(urlStr, cb){
  var mod = urlStr.indexOf('https:') === 0 ? https_resolver : http_resolver;
  var finished = false;
  function done(e, s, b, h){ if(finished){ return; } finished = true; cb(e, s, b, h); }
  try {
    var req = mod.get(urlStr, function(resp){
      var data = '';
      resp.on('data', function(c){ if(data.length < 200000){ data += c; } });
      resp.on('end', function(){ done(null, resp.statusCode, data, resp.headers || {}); });
    });
    req.on('error', function(e){ done(e); });
    req.setTimeout(12000, function(){ req.destroy(new Error('timeout')); });
  } catch(e){ done(e); }
}

// "Unclaimed resource" fingerprints for common takeover-prone services. A hit needs
// the body signature; a matching CNAME raises confidence to high. Curated from the
// well-known can-i-take-over-xyz signatures.
var TAKEOVER_FPS = [
  { service: 'GitHub Pages', cname: ['github.io'], body: ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"] },
  { service: 'AWS S3', cname: ['s3.amazonaws.com', 's3-website', 's3.'], body: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { service: 'Heroku', cname: ['herokudns.com', 'herokuapp.com', 'herokussl.com'], body: ['No such app', "There's nothing here, yet."] },
  { service: 'Microsoft Azure', cname: ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net', 'azureedge.net', 'azurefd.net'], body: ['404 Web Site not found', 'The resource you are looking for has been removed'] },
  { service: 'Fastly', cname: ['fastly.net'], body: ['Fastly error: unknown domain'] },
  { service: 'Shopify', cname: ['myshopify.com'], body: ['Sorry, this shop is currently unavailable'] },
  { service: 'Tumblr', cname: ['domains.tumblr.com'], body: ["Whatever you were looking for doesn't currently exist at this address"] },
  { service: 'Zendesk', cname: ['zendesk.com'], body: ['Help Center Closed'] },
  { service: 'Ghost', cname: ['ghost.io'], body: ['The thing you were looking for is no longer here'] },
  { service: 'Surge.sh', cname: ['surge.sh'], body: ['project not found'] },
  { service: 'Pantheon', cname: ['pantheonsite.io'], body: ['The gods are wise, but do not know of the site which you seek', '404 error unknown site!'] },
  { service: 'Bitbucket', cname: ['bitbucket.io'], body: ['Repository not found'] },
  { service: 'Netlify', cname: ['netlify.app', 'netlify.com'], body: ['Not Found - Request ID'] },
  { service: 'Read the Docs', cname: ['readthedocs.io'], body: ['unknown to Read the Docs'] },
  { service: 'WordPress', cname: ['wordpress.com'], body: ['Do you want to register'] },
  { service: 'Desk', cname: ['desk.com'], body: ['Please try again or try Desk.com free for 14 days'] },
  { service: 'Cargo', cname: ['cargocollective.com'], body: ['404 Not Found'] }
];

// Fetch a host and, on a matching "unclaimed" signature, emit a vuln finding node.
function checkTakeover(host, cnames, io, cb){
  var schemes = ['https://' + host + '/', 'http://' + host + '/'];
  function tryScheme(i){
    if(i >= schemes.length){ cb(false); return; }
    httpGetBody(schemes[i], function(err, status, body){
      if(err || body === undefined || body === null){ tryScheme(i + 1); return; }
      var hitFp = null, cnameHit = false;
      for(var f = 0; f < TAKEOVER_FPS.length; f++){
        var fp = TAKEOVER_FPS[f];
        var bodyMatch = fp.body.some(function(sig){ return body.indexOf(sig) > -1; });
        if(!bodyMatch){ continue; }
        var cnameMatch = cnames.some(function(c){ return fp.cname.some(function(suf){ return String(c).toLowerCase().indexOf(suf) > -1; }); });
        hitFp = fp; cnameHit = cnameMatch;
        if(cnameMatch){ break; }   // prefer a CNAME-corroborated match
      }
      if(hitFp){
        var cnameStr = cnames.join(', ');
        io.emit('add_node', { id: 'TAKEOVER? ' + host + ' -> ' + hitFp.service, parent: host, node_type: 'vuln',
          label: '⚠ Takeover? ' + hitFp.service,
          meta: { host: host, service: hitFp.service, cname: cnameStr || '(none)', status: String(status),
                  confidence: cnameHit ? 'high (CNAME + body signature)' : 'medium (body signature only)' } });
        cb(true);
      } else {
        cb(false);
      }
    });
  }
  tryScheme(0);
}

// Derive candidate bucket names from a domain or org node (base keyword x suffixes).
function bucketCandidates(seed){
  var base = String(seed).toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  var labels = base.split('.').filter(Boolean);
  var core;
  if(labels.length >= 2 && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(base)){ core = labels[labels.length - 2]; }
  else { core = base.replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, ''); }
  var bases = {};
  if(core){ bases[core] = 1; bases[core.replace(/-/g, '')] = 1; }
  var suffixes = ['', '-www', '-dev', '-staging', '-prod', '-test', '-backup', '-backups', '-assets',
                  '-static', '-media', '-images', '-files', '-uploads', '-data', '-logs', '-public',
                  '-private', '-internal', '-cdn', '-app'];
  var seen = {}, out = [];
  Object.keys(bases).forEach(function(b){
    if(!b){ return; }
    suffixes.forEach(function(suf){
      [b + suf, suf ? b + suf.replace('-', '') : null].forEach(function(n){
        if(n && n.length >= 3 && !seen[n]){ seen[n] = 1; out.push(n); }
      });
    });
  });
  return out.slice(0, 30);
}

// Probe one candidate name across S3, GCS, and Azure Blob. cb(true) if anything exists.
function checkBucket(name, seed, io, cb){
  var any = false;
  httpGetBody('https://' + name + '.s3.amazonaws.com/', function(e, s, b){
    var bb = b || '';
    if(!e && s){
      if(s === 200 && bb.indexOf('<ListBucketResult') > -1){
        any = true;
        io.emit('add_node', { id: '⚠ PUBLIC S3: https://' + name + '.s3.amazonaws.com/', parent: seed, node_type: 'vuln',
          label: '⚠ Public S3 bucket: ' + name,
          meta: { provider: 'AWS S3', bucket: name, access: 'PUBLIC / listable', url: 'https://' + name + '.s3.amazonaws.com/' } });
      } else if(s === 403 || bb.indexOf('AccessDenied') > -1){
        any = true;
        io.emit('add_node', { id: 'S3 (private): https://' + name + '.s3.amazonaws.com/', parent: seed, node_type: 'info',
          meta: { provider: 'AWS S3', bucket: name, access: 'exists (private)' } });
      } else if(bb.indexOf('PermanentRedirect') > -1){
        any = true;
        io.emit('add_node', { id: 'S3 (region redirect): https://' + name + '.s3.amazonaws.com/', parent: seed, node_type: 'info',
          meta: { provider: 'AWS S3', bucket: name, access: 'exists (other region)' } });
      }
    }
    httpGetBody('https://storage.googleapis.com/' + name + '/', function(e2, s2){
      if(!e2 && s2 === 200){
        any = true;
        io.emit('add_node', { id: '⚠ PUBLIC GCS: https://storage.googleapis.com/' + name + '/', parent: seed, node_type: 'vuln',
          label: '⚠ Public GCS bucket: ' + name,
          meta: { provider: 'Google GCS', bucket: name, access: 'PUBLIC / listable', url: 'https://storage.googleapis.com/' + name + '/' } });
      } else if(!e2 && s2 === 403){
        any = true;
        io.emit('add_node', { id: 'GCS (private): https://storage.googleapis.com/' + name + '/', parent: seed, node_type: 'info',
          meta: { provider: 'Google GCS', bucket: name, access: 'exists (private)' } });
      }
      dns.resolve(name + '.blob.core.windows.net', function(e3){
        if(!e3){
          any = true;
          io.emit('add_node', { id: 'Azure blob: https://' + name + '.blob.core.windows.net/', parent: seed, node_type: 'info',
            meta: { provider: 'Azure Blob', account: name, access: 'storage account exists' } });
        }
        cb(any);
      });
    });
  });
}
