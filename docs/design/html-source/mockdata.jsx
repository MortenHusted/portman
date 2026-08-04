// Mock data for all 10 portman UI states.

const PM_ENTRIES_HAPPY = [
  { host: 'crm.test',        target: '172.19.0.4:3000',  source: 'container', containerID: 'a3f2b1', tld: 'test',  cert: 'ready'  },
  { host: 'api.test',        target: '172.19.0.5:8080',  source: 'container', containerID: '8d91ec', tld: 'test',  cert: 'ready'  },
  { host: 'admin.test',      target: '172.19.0.8:4000',  source: 'container', containerID: '2b04a7', tld: 'test',  cert: 'ready'  },
  { host: 'billing.test',    target: '172.19.0.11:5000', source: 'container', containerID: '6e3f22', tld: 'test',  cert: 'pending'},
  { host: 'mail.test',       target: '127.0.0.1:1025',   source: 'static',    containerID: null,     tld: 'test',  cert: 'ready'  },
  { host: 'web.sofus',       target: '127.0.0.1:3000',   source: 'static',    containerID: null,     tld: 'sofus', cert: 'none'   },
  { host: 'api.sofus',       target: '127.0.0.1:3070',   source: 'static',    containerID: null,     tld: 'sofus', cert: 'none'   },
];

const PM_ENTRIES_HOVER = PM_ENTRIES_HAPPY.map((e, i) => {
  // one https entry flagged with error for the hover-states board
  if (i === 3) return { ...e, cert: 'error' };
  return e;
});

const PM_ENTRIES_WINDOW = [
  // test / mkcert
  { host: 'crm.test',        target: '172.19.0.4:3000',   source: 'container', containerID: 'a3f2b1d9e0', tld: 'test',  cert: 'ready'  },
  { host: 'api.test',        target: '172.19.0.5:8080',   source: 'container', containerID: '8d91ec4412', tld: 'test',  cert: 'ready'  },
  { host: 'admin.test',      target: '172.19.0.8:4000',   source: 'container', containerID: '2b04a71fc3', tld: 'test',  cert: 'ready'  },
  { host: 'billing.test',    target: '172.19.0.11:5000',  source: 'container', containerID: '6e3f22a8bb', tld: 'test',  cert: 'pending'},
  { host: 'notifier.test',   target: '172.19.0.12:5050',  source: 'container', containerID: 'fa0c9931de', tld: 'test',  cert: 'ready'  },
  { host: 'queue.test',      target: '172.19.0.15:6379',  source: 'container', containerID: '4c7de801aa', tld: 'test',  cert: 'ready'  },
  { host: 'pgsql.test',      target: '172.19.0.21:5432',  source: 'container', containerID: 'e9b1c0f743', tld: 'test',  cert: 'ready'  },
  { host: 'mail.test',       target: '127.0.0.1:1025',    source: 'static',    containerID: null,         tld: 'test',  cert: 'ready'  },
  { host: 'docs.test',       target: '127.0.0.1:4444',    source: 'static',    containerID: null,         tld: 'test',  cert: 'ready'  },
  // sofus / http
  { host: 'web.sofus',       target: '127.0.0.1:3000',    source: 'static',    containerID: null,         tld: 'sofus', cert: 'none'   },
  { host: 'api.sofus',       target: '127.0.0.1:3070',    source: 'static',    containerID: null,         tld: 'sofus', cert: 'none'   },
  { host: 'worker.sofus',    target: '127.0.0.1:3080',    source: 'static',    containerID: null,         tld: 'sofus', cert: 'none'   },
  // crm / mkcert
  { host: 'app.crm',         target: '172.20.0.3:3000',   source: 'container', containerID: '7a220ef5a1', tld: 'crm',   cert: 'ready'  },
  { host: 'api.crm',         target: '172.20.0.4:3001',   source: 'container', containerID: 'cc8a40b2f1', tld: 'crm',   cert: 'ready'  },
  { host: 'ws.crm',          target: '172.20.0.5:3002',   source: 'container', containerID: 'fe10d22aaa', tld: 'crm',   cert: 'ready'  },
  { host: 'reports.crm',     target: '172.20.0.8:4500',   source: 'container', containerID: '021bbcd18e', tld: 'crm',   cert: 'pending'},
  { host: 'minio.crm',       target: '172.20.0.10:9000',  source: 'container', containerID: '44309a8801', tld: 'crm',   cert: 'ready'  },
  // local / http
  { host: 'pgadmin.local.dev', target: '127.0.0.1:5050',  source: 'static',    containerID: null,         tld: 'local.dev', cert: 'none' },
  { host: 'dash.local.dev',  target: '127.0.0.1:9999',    source: 'static',    containerID: null,         tld: 'local.dev', cert: 'none' },
  { host: 'search.local.dev',target: '127.0.0.1:9200',    source: 'static',    containerID: null,         tld: 'local.dev', cert: 'none' },
  { host: 'kibana.local.dev',target: '127.0.0.1:5601',    source: 'static',    containerID: null,         tld: 'local.dev', cert: 'none' },
];

const PM_TLDS = [
  { name: 'test',      tlsMode: 'mkcert', entryCount: 9, caTrusted: true  },
  { name: 'sofus',     tlsMode: 'off',    entryCount: 3, caTrusted: false },
  { name: 'crm',       tlsMode: 'mkcert', entryCount: 5, caTrusted: true  },
  { name: 'local.dev', tlsMode: 'off',    entryCount: 4, caTrusted: false },
];

const PM_TLDS_MENUBAR = [
  { name: 'test',  tlsMode: 'mkcert' },
  { name: 'sofus', tlsMode: 'off'    },
];

const PM_STATUS = {
  online: {
    kind: 'online',
    version: '0.6.2',
    runningSince: '3h 42m',
    dnsPort: 53,
    proxyPortHttp: 80,
    proxyPortHttps: 443,
    socketPath: '~/Library/Application Support/portman/portman.sock',
    configPath: '~/Library/Application Support/portman/config.toml',
    certsPath: '~/Library/Application Support/portman/certs',
  },
  offline: {
    kind: 'offline',
    lastSeen: '24m ago',
    version: '0.6.2',
  },
  starting: {
    kind: 'starting',
    message: 'Authenticating with launchctl…',
  },
};

Object.assign(window, {
  PM_ENTRIES_HAPPY,
  PM_ENTRIES_HOVER,
  PM_ENTRIES_WINDOW,
  PM_TLDS,
  PM_TLDS_MENUBAR,
  PM_STATUS,
});
