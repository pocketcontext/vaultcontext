"""Offline browser privacy/regression checks; never contacts analytics providers.

Run: uv run --with playwright python tests/website_analytics.py
Install bundled Chromium with python -m playwright install chromium.
Set PLAYWRIGHT_CHANNEL=chrome to use locally installed Google Chrome.
"""
import json
import mimetypes
import os
import re
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'pb_public'
PRODUCTION = 'https://vault.pocketcontext.com'


def run(browser, origin, path='/', stored=None, fail=False):
    context = browser.new_context(viewport={'width': 390, 'height': 844})
    if stored:
        context.add_init_script(f"localStorage.setItem('vaultcontext.analytics.v1', {json.dumps(stored)})")
    context.add_init_script("Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copied=text}}})")
    external = []
    errors = []
    def route(request):
        url = urlsplit(request.request.url)
        if f'{url.scheme}://{url.netloc}' == origin:
            asset = PUBLIC / (url.path.lstrip('/') or 'index.html')
            if not asset.is_file():
                asset = PUBLIC / 'index.html'
            headers = {'Referrer-Policy': 'no-referrer'}
            hook = (ROOT / 'pb_hooks/frontend.pb.js').read_text()
            match = re.search(r"set\('Content-Security-Policy', (.+)\);", hook)
            if match:
                expression = match.group(1).replace('frameAncestors', json.dumps("'self'" if url.path == '/analytics-frame.html' else "'none'"))
                headers['Content-Security-Policy'] = ''.join(json.loads(part.strip()) for part in expression.split(' + '))
            request.fulfill(body=asset.read_bytes(), content_type=mimetypes.guess_type(str(asset))[0] or 'application/octet-stream', headers=headers)
        else:
            external.append({'url': request.request.url, 'body': request.request.post_data})
            if fail:
                request.abort()
            else:
                request.fulfill(status=200, body='', content_type='application/javascript', headers={'Access-Control-Allow-Origin':'*'})
    context.route('**/*', route)
    page = context.new_page()
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(origin + path)
    page.wait_for_timeout(150)
    return context, page, external, errors


def exercise(page):
    for details in page.locator('#another-computer details').all():
        details.evaluate('(e)=>e.open=true')
    button = page.get_by_label('Copy cross-computer comparison prompt')
    expected = button.locator('..').locator('code').text_content()
    button.click()
    assert page.evaluate('window.copied') == expected
    assert 'Copied.' in page.locator('#copy-status').text_content()
    page.locator('[data-method="agent"]').click()
    assert page.locator('#agent-panel').is_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(channel=os.environ.get('PLAYWRIGHT_CHANNEL'), headless=True)
    for origin, path in [(PRODUCTION,'/'),('http://vault.pocketcontext.com','/'),('https://www.vault.pocketcontext.com','/'),('http://localhost:8769','/'),('https://preview.example.test','/'),('https://vault.pocketcontext.com:8443','/'),(PRODUCTION,'/private')]:
        context, page, external, errors = run(browser, origin, path)
        exercise(page)
        assert not external, (origin, path, external)
        assert not errors, errors
        context.close()
    for origin in ['http://vault.pocketcontext.com', 'https://www.vault.pocketcontext.com', 'http://localhost:8769', 'https://preview.example.test', 'https://vault.pocketcontext.com:8443']:
        context, page, external, errors = run(browser, origin, stored='accepted')
        exercise(page)
        assert not external, (origin, external)
        context.close()
    context, page, external, errors = run(browser, PRODUCTION, '/?private=DO_NOT_SEND#SECRET')
    if os.environ.get('ANALYTICS_SCREENSHOTS'):
        for width in (320, 1440):
            page.set_viewport_size({'width':width,'height':1000})
            page.reload()
            page.wait_for_timeout(150)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            for selector in ('#analytics-accept', '#analytics-reject'):
                assert page.locator(selector).evaluate('(e)=>{const r=e.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===e}')
            page.screenshot(path=f'/private/tmp/vault-analytics-{width}.png')
        page.set_viewport_size({'width':390,'height':844})
    page.locator('#analytics-reject').click()
    exercise(page)
    assert not external
    page.locator('#analytics-settings').click()
    page.locator('#analytics-accept').focus()
    page.keyboard.press('Enter')
    page.wait_for_timeout(200)
    exercise(page)
    page.wait_for_timeout(200)
    assert any('googletagmanager.com' in e['url'] for e in external), external
    assert any('rybbit.getcolors.ai' in e['url'] for e in external), external
    rybbit = [json.loads(e['body']) for e in external if 'rybbit.getcolors.ai' in e['url'] and e['body']]
    assert any(e.get('event_name') == 'onboarding_copy' and json.loads(e['properties']) == {'target': 'compare_prompt'} for e in rybbit)
    for event in rybbit:
        assert event['hostname'] == 'vault.pocketcontext.com' and event['pathname'] == '/'
        assert event['querystring'] == '' and event['referrer'] == ''
        assert event['type'] in ('pageview', 'custom_event')
    assert page.evaluate('window.dataLayer === undefined')
    commands = [frame.evaluate('Array.from(window.dataLayer || [], x=>Array.from(x))') for frame in page.frames]
    payloads = json.dumps(external) + json.dumps(commands, default=str)
    for forbidden in ['DO_NOT_SEND', 'SECRET', '/Users/alex', '/home/alex', 'compare my active', 'DOCUMENT_ID']:
        assert forbidden not in payloads, forbidden
    assert not errors, errors
    page.locator('#analytics-settings').click()
    page.locator('#analytics-reject').click()
    page.wait_for_timeout(100)
    assert page.locator('iframe').count() == 0
    count = len(external)
    exercise(page)
    page.wait_for_timeout(100)
    assert len(external) == count
    context.close()
    # A blocked fetch API must not turn a successful clipboard write into failure.
    context, page, external, errors = run(browser, PRODUCTION, stored='accepted')
    page.evaluate("() => {window.fetch=()=>{throw Error('blocked')}}")
    exercise(page)
    assert not errors
    # A decision in another tab withdraws this tab too.
    page.evaluate("window.dispatchEvent(new StorageEvent('storage',{key:'vaultcontext.analytics.v1',newValue:'rejected'}))")
    assert page.locator('iframe').count() == 0
    context.close()
    for fail in [False, True]:
        context, page, external, errors = run(browser, PRODUCTION, stored='accepted', fail=fail)
        exercise(page)
        assert not errors, errors
        page.evaluate("Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied')}}})")
        page.get_by_label('Copy cross-computer comparison prompt').click()
        assert 'Automatic copy unavailable' in page.locator('#copy-status').text_content()
        context.close()
    context, page, external, errors = run(browser, PRODUCTION, '/analytics-frame.html', stored='accepted')
    assert not external and not errors
    context.close()
    browser.close()
print('PASS: exact-origin/path gate, consent, withdrawal, payload privacy, offline trackers, failure isolation, mobile and keyboard')
