const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '..', 'app', 'templates', 'v2_dashboard.html'), 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const timers = [];
const alertRequests = [];
const historyRequests = [];

function makeElement() {
    return {
        textContent: '', value: 'pcap', disabled: false, className: '', title: '', innerHTML: '',
        classList: { add() {}, remove() {}, toggle() {} },
        children: [], style: {}, attributes: {},
        replaceChildren(...children) { this.children = children; this.innerHTML = ''; },
        append(...children) { this.children.push(...children); },
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener() {}, dispatchEvent() {}, appendChild(child) { this.children.push(child); },
    };
}

const document = {
    getElementById(id) {
        if (!elements.has(id)) elements.set(id, makeElement());
        return elements.get(id);
    },
    createElement: makeElement,
};

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
    return { promise, resolve, reject };
}

const firstAlerts = deferred();
const context = {
    document,
    Event: class Event {},
    console: { error() {} },
    setTimeout(callback) { timers.push(callback); return timers.length; },
    setInterval() { return 1; },
    URLSearchParams,
    Date,
    fetch(url) {
        if (url === '/api/v2/interfaces') {
            return Promise.resolve({ ok: true, json: async () => ({ interfaces: [] }) });
        }
        if (url.startsWith('/api/v2/history/')) {
            historyRequests.push(url);
            const topTalkers = url.startsWith('/api/v2/history/top-talkers');
            return Promise.resolve({ ok: true, json: async () => topTalkers
                ? { available: false, reason: 'No address metadata', talkers: [] }
                : { buckets: [], window: '24h', origin_filter: 'pcap', bucket_seconds: 900, timezone: 'UTC' } });
        }
        alertRequests.push(url);
        if (alertRequests.length === 1) return firstAlerts.promise;
        return Promise.reject(new Error('offline'));
    },
};

async function settle() {
    for (let i = 0; i < 8; i++) await Promise.resolve();
}

async function main() {
    vm.runInNewContext(script, context);
    await settle();
    assert.equal(alertRequests.length, 1, 'initial dashboard request starts once');
    assert.equal(historyRequests.length, 2, 'trends and Top Talkers poll independently of live status');

    firstAlerts.resolve({
        ok: true,
        json: async () => ({
            alerts: [],
            feed: [
                { label: 'ATTACK', timestamp: '12:34:55', src_ip: '192.0.2.1', src_port: 443,
                    dst_ip: '198.51.100.1', dst_port: 5000, protocol: 'TCP', packets: 5, confidence: 91 },
                { label: 'BENIGN', timestamp: '12:34:56', src_ip: '192.0.2.2', src_port: 80,
                    dst_ip: '198.51.100.2', dst_port: 5001, protocol: 'TCP', packets: 2, confidence: 88 },
            ],
            status: {
                is_running: true,
                mode: 'pcap',
                active_interface: 'Replay: test.pcap',
                model_available: true,
                email_alerts: { state: 'disabled', message: 'Email alerts are disabled.',
                    pending: 2, delivered: 4, failed: 1 },
                stats: {
                    packets_processed: 14912,
                    active_flows: 524,
                    completed_flows: 2395,
                    benign_count: 2395,
                    attack_count: 0,
                    attacks_flagged: 5,
                    processing_errors: 0,
                    capture_errors: 0,
                },
            },
        }),
    });
    await settle();
    assert.equal(elements.get('kpiPackets').textContent, '14,912');
    assert.equal(elements.get('kpiActiveFlows').textContent, '524');
    assert.equal(elements.get('kpiCompletedFlows').textContent, '2,395');
    assert.equal(elements.get('healthEmailAlerts').textContent,
        'Email alerts: Email alerts are disabled. · 2 pending, 4 delivered, 1 failed');
    assert.equal(elements.get('kpiBenign').textContent, '2,395');
    assert.equal(elements.get('kpiAttacks').textContent, '5', 'attacks flagged includes simulated attack predictions');
    assert.equal(elements.get('kpiAttackRate').textContent, '0.0%');
    assert.equal(elements.get('kpiRecentAlerts').textContent, '0');
    assert.equal(elements.get('alertTableBody').children.length, 2, 'feed renders attacks and benign classifications');
    assert.match(elements.get('historyStatus').textContent, /No stored events/);
    assert.match(elements.get('talkersStatus').textContent, /No address metadata/);
    assert.deepEqual(elements.get('alertTableBody').children.map(row => row.className), ['row-attack', 'row-benign']);
    assert.equal(timers.length, 1, 'next refresh is scheduled after the response settles');

    timers.shift()();
    await settle();
    assert.equal(alertRequests.length, 2, 'only one follow-up request starts');
    assert.equal(elements.get('kpiPackets').textContent, '—', 'failed poll clears stale packet count');
    assert.equal(elements.get('kpiCompletedFlows').textContent, '—', 'failed poll clears stale flow count');
    assert.match(elements.get('statusBannerText').textContent, /connection error/);
    assert.equal(elements.get('healthEmailAlerts').textContent, 'Email alerts: status unavailable');
    assert.match(elements.get('alertTableBody').innerHTML, /data is unavailable/);
    assert.equal(timers.length, 1, 'polling retries after a failed response');

    const hostedElements = new Map();
    const hostedTimers = [];
    const hostedContext = {
        document: {
            getElementById(id) {
                if (!hostedElements.has(id)) hostedElements.set(id, makeElement());
                return hostedElements.get(id);
            },
            createElement: makeElement,
        },
        Event: class Event {},
        console: { error() {} },
        setTimeout(callback) { hostedTimers.push(callback); return hostedTimers.length; },
        setInterval() { return 1; },
        URLSearchParams,
        Date,
        fetch(url) {
            if (url === '/api/v2/interfaces') {
                return Promise.resolve({ ok: false, status: 403 });
            }
            if (url.startsWith('/api/v2/history/')) {
                const topTalkers = url.startsWith('/api/v2/history/top-talkers');
                return Promise.resolve({ ok: true, json: async () => topTalkers
                    ? { available: false, reason: 'Stored endpoint metadata is unavailable', talkers: [] }
                    : { buckets: [], window: '24h', origin_filter: 'live', bucket_seconds: 900, timezone: 'UTC' } });
            }
            return Promise.resolve({ ok: true, json: async () => ({
                alerts: [], feed: [], feed_available: false,
                feed_reason: 'Hosted history does not store local flow details.',
                status: { runtime_role: 'hosted_web', is_running: false, model_available: false,
                    stats: { packets_processed: null, active_flows: null, completed_flows: null,
                        benign_count: null, attacks_flagged: null, classified_flows: null,
                        threat_level: 'UNAVAILABLE', capture_errors: null, processing_errors: null },
                },
            }) });
        },
    };
    vm.runInNewContext(script, hostedContext);
    await settle();
    assert.match(hostedElements.get('statusBannerText').textContent, /Hosted web role ready/);
    assert.equal(hostedElements.get('kpiPackets').textContent, '—', 'hosted mode does not invent local counters');
    assert.equal(hostedElements.get('btnStart').disabled, true, 'hosted mode disables capture controls');
    assert.equal(hostedElements.get('btnSimulate').disabled, true, 'hosted mode disables simulation controls');
    assert.match(hostedElements.get('alertTableBody').innerHTML, /does not store local flow details/);
    assert.equal(hostedTimers.length, 1, 'hosted dashboard continues polling');

    const unavailableElements = new Map();
    const unavailableTimers = [];
    const unavailableContext = {
        document: {
            getElementById(id) {
                if (!unavailableElements.has(id)) unavailableElements.set(id, makeElement());
                return unavailableElements.get(id);
            },
            createElement: makeElement,
        },
        Event: class Event {},
        console: { error() {} },
        setTimeout(callback) { unavailableTimers.push(callback); return unavailableTimers.length; },
        setInterval() { return 1; },
        URLSearchParams,
        Date,
        fetch(url) {
            if (url === '/api/v2/interfaces') {
                return Promise.resolve({ ok: true, json: async () => ({ interfaces: [] }) });
            }
            if (url.startsWith('/api/v2/history/')) {
                const topTalkers = url.startsWith('/api/v2/history/top-talkers');
                return Promise.resolve({ ok: true, json: async () => topTalkers
                    ? { available: false, reason: 'No address metadata', talkers: [] }
                    : { buckets: [], window: '24h', origin_filter: 'live', bucket_seconds: 900, timezone: 'UTC' } });
            }
            return Promise.resolve({ ok: true, json: async () => ({ alerts: [], feed: [], status: {
                is_running: false, mode: 'idle', model_available: false,
                model_status_message: 'V2 model unavailable. Restore the expected model artifact and restart the local sensor.',
                stats: { packets_processed: 0, active_flows: 0, completed_flows: 0, benign_count: 0,
                    attacks_flagged: 0, classified_flows: 0, threat_level: 'LOW', capture_errors: 0,
                    processing_errors: 0 },
            } }) });
        },
    };
    vm.runInNewContext(script, unavailableContext);
    await settle();
    assert.match(unavailableElements.get('healthModel').textContent, /model unavailable.*restart the local sensor/i);
    assert.match(unavailableElements.get('statusBannerText').textContent, /restore the expected model artifact/i);
    assert.equal(unavailableElements.get('btnStart').disabled, true,
        'local capture stays disabled while the required model is unavailable');
    assert.equal(unavailableElements.get('btnSimulate').disabled, true,
        'model-based simulation stays disabled while the required model is unavailable');
    assert.equal(unavailableTimers.length, 1, 'unavailable model state continues polling');

    const shutdownElements = new Map();
    const shutdownWarning = 'Capture shutdown is still in progress; capture resources remain open. Check the local sensor if it does not stop.';
    const shutdownContext = {
        document: {
            getElementById(id) {
                if (!shutdownElements.has(id)) shutdownElements.set(id, makeElement());
                return shutdownElements.get(id);
            },
            createElement: makeElement,
        },
        Event: class Event {},
        console: { error() {} },
        setTimeout(callback) { return 1; },
        setInterval() { return 1; },
        URLSearchParams,
        Date,
        fetch(url) {
            if (url === '/api/v2/interfaces') {
                return Promise.resolve({ ok: true, json: async () => ({ interfaces: [] }) });
            }
            if (url.startsWith('/api/v2/history/')) {
                const topTalkers = url.startsWith('/api/v2/history/top-talkers');
                return Promise.resolve({ ok: true, json: async () => topTalkers
                    ? { available: false, reason: 'No address metadata', talkers: [] }
                    : { buckets: [], window: '24h', origin_filter: 'live', bucket_seconds: 900, timezone: 'UTC' } });
            }
            if (url === '/api/v2/stop') {
                return Promise.resolve({ ok: true, json: async () => ({
                    success: false, message: 'Stop requested, but the capture worker did not stop before the timeout.',
                    status: { is_running: true, stop_requested: true, shutdown_warning: shutdownWarning,
                        mode: 'live', model_available: true, stats: { capture_errors: 0, processing_errors: 0 } },
                }) });
            }
            return Promise.resolve({ ok: true, json: async () => ({ alerts: [], feed: [], status: {
                is_running: true, stop_requested: true, shutdown_warning: shutdownWarning,
                mode: 'live', active_interface: 'mock-interface', model_available: true,
                stats: { packets_processed: 0, active_flows: 0, completed_flows: 0,
                    benign_count: 0, attacks_flagged: 0, classified_flows: 0, threat_level: 'LOW',
                    capture_errors: 0, processing_errors: 0 },
            } }) });
        },
    };
    vm.runInNewContext(script, shutdownContext);
    await settle();
    await shutdownContext.stopSniffer();
    assert.match(shutdownElements.get('statusBannerText').textContent, /capture shutdown is still in progress/i,
        'dashboard displays the sanitized capture shutdown timeout');
    console.log('Dashboard polling behavior passed.');
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
