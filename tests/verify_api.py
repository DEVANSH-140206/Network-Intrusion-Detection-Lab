"""Quick API verification script - run while Flask server is running"""
import urllib.request, json, sys

def get(path):
    with urllib.request.urlopen(f'http://127.0.0.1:5000{path}', timeout=5) as r:
        return json.loads(r.read())

errors = []

try:
    h = get('/api/health')
    print(f'HEALTH: {h}')
    assert h['status'] == 'ok'
except Exception as e:
    errors.append(f'health: {e}')

try:
    s = get('/api/stats')
    print(f'STATS: total={s["total_alerts"]} crit={s["critical"]} high={s["high"]} med={s["medium"]} low={s["low"]}')
    assert s['total_alerts'] > 0
except Exception as e:
    errors.append(f'stats: {e}')

try:
    a = get('/api/alerts?per_page=3')
    print(f'ALERTS: total={a["total"]} page={a["page"]} returned={len(a["alerts"])}')
    assert a['total'] > 0
    aid = a['alerts'][0]['id']
    d = get(f'/api/alerts/{aid}')
    print(f'DETAIL: sig={d["signature"][:55]} sev={d["severity_label"]}')
    assert 'raw' in d
except Exception as e:
    errors.append(f'alerts: {e}')

try:
    t = get('/api/timeline')
    print(f'TIMELINE: {len(t)} buckets')
    # Check sorted
    times = [x['time'] for x in t]
    assert times == sorted(times)
except Exception as e:
    errors.append(f'timeline: {e}')

try:
    p = get('/api/protocols')
    print(f'PROTOCOLS: {p}')
    assert len(p) > 0
except Exception as e:
    errors.append(f'protocols: {e}')

try:
    ts = get('/api/top-sources?limit=5')
    print(f'TOP SOURCES: {[(x["ip"], x["count"]) for x in ts[:3]]}')
except Exception as e:
    errors.append(f'top-sources: {e}')

try:
    td = get('/api/top-destinations?limit=5')
    print(f'TOP DESTINATIONS: {[(x["ip"], x["count"]) for x in td[:3]]}')
except Exception as e:
    errors.append(f'top-destinations: {e}')

try:
    r = get('/api/rules')
    print(f'RULES: total={r["total"]} is_demo={r["is_demo"]}')
    assert r['total'] > 0
except Exception as e:
    errors.append(f'rules: {e}')

try:
    st = get('/api/system-status')
    for c in st['components']:
        print(f'  STATUS {c["name"]}: {c["status"]}')
    flask_comp = next((c for c in st['components'] if c['name'] == 'Flask Backend'), None)
    assert flask_comp['status'] == 'ONLINE'
except Exception as e:
    errors.append(f'system-status: {e}')

try:
    fs = get('/api/alerts?search=Nmap&per_page=5')
    print(f'SEARCH nmap: {fs["total"]} results')
except Exception as e:
    errors.append(f'search: {e}')

try:
    sc = get('/api/alerts?severity=critical')
    print(f'FILTER critical: {sc["total"]} alerts')
    for a in sc['alerts']:
        assert a['severity'] == 1
except Exception as e:
    errors.append(f'severity-filter: {e}')

try:
    fp = get('/api/flow-pairs')
    print(f'FLOW PAIRS: {len(fp)} pairs')
except Exception as e:
    errors.append(f'flow-pairs: {e}')

try:
    fopts = get('/api/filter-options')
    print(f'FILTER OPTIONS: cats={len(fopts["categories"])} protos={len(fopts["protocols"])}')
except Exception as e:
    errors.append(f'filter-options: {e}')

try:
    plist = get('/api/pcap/list')
    print(f'PCAP LIST: {len(plist["files"])} files')
except Exception as e:
    errors.append(f'pcap-list: {e}')

try:
    # Test 404 for missing alert
    try:
        get('/api/alerts/9999999')
        errors.append('alert-404: did not return 404')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print('ALERT 404: correctly returns 404')
        else:
            errors.append(f'alert-404: wrong status {e.code}')
except Exception as e:
    errors.append(f'alert-404-test: {e}')

print()
if errors:
    print(f'ERRORS ({len(errors)}):')
    for err in errors:
        print(f'  - {err}')
    sys.exit(1)
else:
    print('ALL API ENDPOINTS VERIFIED: OK')
