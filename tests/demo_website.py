"""Offline demo UI checks. All live-mode requests use synthetic intercepted routes.
Run: uv run --with playwright==1.60.0 python tests/demo_website.py
Set PLAYWRIGHT_EXECUTABLE_PATH only when using an already installed browser.
"""
from playwright.sync_api import sync_playwright
from pathlib import Path
import json
import hashlib
from urllib.parse import urlsplit
import os
ROOT=Path(__file__).resolve().parents[1]/'pb_public'/'demo'
BROWSER=os.environ.get('PLAYWRIGHT_EXECUTABLE_PATH')
for asset in ('styles.css','app.js'):
 digest=hashlib.sha256((ROOT/asset).read_bytes()).hexdigest()[:12]
 assert f'{asset}?v={digest}' in (ROOT/'index.html').read_text(),f'Stale asset hash: {asset}'
with sync_playwright() as p:
 b=p.chromium.launch(**({'executable_path':BROWSER} if BROWSER else {}))
 page=b.new_page(viewport={'width':390,'height':844})
 page.goto((ROOT/'index.html').as_uri());page.locator('#google-button').click();page.locator('#terms').check();page.locator('.continue-button').click()
 assert page.locator('#onboarding').is_visible()
 assert not page.locator('#commercial').is_checked() and not page.locator('#newsletter').is_checked()
 assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 page.locator('[data-method="agent"]').click();assert page.locator('#agent-note').is_visible()
 for d in page.locator('.guide-steps details').all():d.evaluate('(el)=>el.open=true')
 for c in page.locator('.step-done').all():c.check()
 assert page.locator('#guide-complete').is_visible();page.locator('#reset-progress').click();assert not page.locator('#guide-complete').is_visible()
 page.locator('a[href="#privacy-details"]').click();assert page.locator('#privacy-details').get_attribute('open') is not None
 page.close()
 page=b.new_page(viewport={'width':1440,'height':1000});calls=[];errors=[];pending_enroll=[];fail_preferences=False;client_ready=False;public_downloads=None
 page.on('pageerror',lambda error:errors.append(str(error)))
 def route(r):
  path=urlsplit(r.request.url).path;calls.append((path,r.request.post_data))
  def result(x,status=200):r.fulfill(status=status,content_type='application/json',body=json.dumps(x))
  if path=='/api/demo/status':return result({'enabled':True,'generation':'2099-01-01','resetAt':'2099-01-02T00:00:00Z','termsVersion':'v1','clientReady':client_ready,'downloads':public_downloads})
  if path=='/api/collections/users/auth-methods':return result({'oauth2':{'providers':[{'name':'google','authURL':'https://accounts.google.com/o/oauth2/auth?client_id=synthetic&redirect_uri=','codeVerifier':'synthetic-verifier'}]}})
  if path=='/api/realtime':return r.fulfill(status=204)
  if path=='/api/collections/users/auth-with-oauth2':return result({'token':'synthetic-token','record':{'id':'synthetic','collectionName':'users','email':'demo@example.com','name':'Synthetic Visitor'}})
  if path=='/api/demo/preferences':
   if fail_preferences:return result({'message':'resetting'},503)
   return result({'revision':0,'salesContact':False,'newsletter':False})
  if path=='/api/demo/enroll':
   body=json.loads(r.request.post_data);assert body['salesConsent']==False and body['newsletterConsent']==False and body['expectedRevision']==0
   pending_enroll.append(r);return
  if path=='/api/demo/unsubscribe':return result({'ok':True})
  target=ROOT/('index.html' if path=='/' else path.lstrip('/'))
  if target.is_dir():target=target/'index.html'
  if target.is_file():return r.fulfill(path=str(target))
  r.fulfill(status=404,body='Not found')
 page.route('**/*',route)
 page.add_init_script('''class FakeEventSource { constructor(){window.fakeStream=this;this.listeners={};setTimeout(()=>this.listeners.PB_CONNECT?.({data:JSON.stringify({clientId:'synthetic-state'})}),20);}addEventListener(n,cb){this.listeners[n]=cb;}close(){}}window.EventSource=FakeEventSource;window.open=()=>({closed:false,close(){this.closed=true;},location:{set href(value){setTimeout(()=>window.fakeStream.listeners['@oauth2']({data:JSON.stringify({state:'synthetic-state',code:'synthetic-code'})}),20);}}});''')
 page.goto('http://demo.test/');page.wait_for_function('document.querySelector("#mode-pill").textContent === "Daily reset"')
 page.locator('#google-button').click();page.wait_for_selector('#identity:visible');assert 'Synthetic Visitor' in page.locator('#identity').inner_text()
 page.locator('#terms').check();page.locator('.continue-button').click()
 page.wait_for_function('document.querySelector("#signout").disabled')
 assert pending_enroll
 page.locator('#signout').evaluate('(button)=>button.click()')
 assert page.locator('#identity').is_visible(), 'Signout must not race a pending enrollment'
 pending_enroll.pop().fulfill(status=200,content_type='application/json',body=json.dumps({'enrolled':True,'generation':'2099-01-01','contact':{'revision':1,'unsubscribeToken':'synthetic-withdrawal'}}))
 page.wait_for_selector('#onboarding:visible')
 assert 'example.invalid' in page.locator('#connect-code').text_content();assert 'distribution pending' in page.locator('#guide-intro').inner_text();assert 'Demo enrollment saved' in page.locator('#form-status').inner_text()
 assert not page.evaluate('localStorage.length')
 fail_preferences=True
 page.evaluate("live.resetAt = new Date(Date.now() - 1000).toISOString(); updateCountdown();")
 page.locator('#withdraw').click();page.wait_for_function('document.querySelector("#form-status").textContent.includes("withdrawn")')
 page.wait_for_function('document.querySelector("#preferences-status").textContent.includes("Withdrawal succeeded")')
 page.wait_for_timeout(1100)
 assert 'withdrawn' in page.locator('#form-status').inner_text(), 'Reset timer must not overwrite withdrawal success'
 assert not page.locator('#commercial').is_checked() and not page.locator('#newsletter').is_checked()
 page.locator('#signout').click();assert not page.locator('#identity').is_visible()
 assert not errors,errors
 assert any(x[0]=='/api/demo/enroll' for x in calls)
 # A backend readiness flag cannot make private source publicly installable.
 # Keep the local distribution gate closed even if an old backend says ready.
 client_ready=True;fail_preferences=False
 page.goto('http://demo.test/');page.wait_for_function('document.querySelector("#mode-pill").textContent === "Daily reset"')
 install=page.locator('#install-code').text_content()
 assert 'Public downloads are not connected' in install
 assert 'github.com' not in install and 'uv tool install' not in install
 page.locator('#google-button').click();page.wait_for_selector('#identity:visible');page.locator('#terms').check();page.locator('.continue-button').click()
 page.wait_for_function('document.querySelector("#signout").disabled')
 pending_enroll.pop().fulfill(status=200,content_type='application/json',body=json.dumps({'enrolled':True,'generation':'2099-01-01','contact':{'revision':1,'unsubscribeToken':'synthetic-withdrawal'}}))
 page.wait_for_selector('#onboarding:visible')
 assert 'example.invalid' in page.locator('#connect-code').text_content()
 page.locator('[data-method="agent"]').click()
 assert 'Public downloads are not connected' in page.locator('#install-code').text_content()
 assert 'npx skills add' not in page.locator('#install-code').text_content()
 assert not errors,errors
 # Same-origin checked metadata enables public, hash-pinned distribution.
 release='0.1.0-'+'a'*20
 public_downloads={'schema':1,'package':'vaultcontext-client','version':'0.1.0','release':release,'origin':'http://demo.test','artifacts':{}}
 for key,name in [('wheel','vaultcontext_client-0.1.0-py3-none-any.whl'),('skill','vaultcontext-skill.tar.gz'),('launcher','vaultcontext')]:
  public_downloads['artifacts'][key]={'path':'/demo/downloads/'+release+'/'+name,'sha256':'b'*64,'size':128}
 page.goto('http://demo.test/');page.wait_for_function('document.querySelector("#install-code").textContent.includes("uv tool install --force")')
 assert '#sha256='+'b'*64 in page.locator('#install-code').text_content()
 assert 'github.com' not in page.locator('#install-code').text_content()
 page.locator('#google-button').click();page.wait_for_selector('#identity:visible');page.locator('#terms').check();page.locator('.continue-button').click()
 page.wait_for_function('document.querySelector("#signout").disabled')
 pending_enroll.pop().fulfill(status=200,content_type='application/json',body=json.dumps({'enrolled':True,'generation':'2099-01-01','contact':{'revision':1,'unsubscribeToken':'synthetic-withdrawal'}}))
 page.wait_for_selector('#onboarding:visible')
 assert "VAULTCONTEXT_URL='http://demo.test'" in page.locator('#connect-code').text_content()
 page.locator('[data-method="agent"]').click()
 install=page.locator('#install-code').text_content()
 assert 'shasum -a 256 -c - &&' in install and install.index('shasum')<install.index('tar -xzf')
 assert 'github.com' not in install
 # Invalid checksum/path/origin metadata must fail closed even with ready=true.
 for field,value in [('sha256','invalid'),('path','/private/download.whl')]:
  previous=public_downloads['artifacts']['wheel'][field]
  public_downloads['artifacts']['wheel'][field]=value
  page.goto('http://demo.test/');page.wait_for_function('document.querySelector("#mode-pill").textContent === "Daily reset"')
  assert 'uv tool install' not in page.locator('#install-code').text_content()
  public_downloads['artifacts']['wheel'][field]=previous
 public_downloads['origin']='https://untrusted.example'
 page.goto('http://demo.test/');page.wait_for_function('document.querySelector("#mode-pill").textContent === "Daily reset"')
 assert 'uv tool install' not in page.locator('#install-code').text_content()
 page.close()
 # A capability link remains useful after reset/account deletion. Merely opening
 # the page must never invoke the state-changing POST, and failures are retryable.
 for status_mode in ('resetting', 'offline'):
  page=b.new_page();capability='synthetic_capability_'+'x'*24;withdrawals=[];attempts=[]
  def capability_route(r):
   path=urlsplit(r.request.url).path
   assert capability not in r.request.url
   assert capability not in r.request.headers.get('referer','')
   if path=='/api/demo/status':
    if status_mode=='offline':return r.abort('failed')
    return r.fulfill(status=503,content_type='application/json',body='{}')
   if path=='/api/demo/unsubscribe':
    assert r.request.method=='POST' and 'authorization' not in r.request.headers
    assert json.loads(r.request.post_data)=={'token':capability}
    attempts.append(1)
    if len(attempts)==1:return r.abort('failed')
    withdrawals.append(1);return r.fulfill(status=200,content_type='application/json',body='{"ok":true}')
   target=ROOT/('index.html' if path=='/' else path.lstrip('/'))
   if target.is_file():return r.fulfill(path=str(target))
   r.fulfill(status=404,body='Not found')
  page.route('**/*',capability_route)
  page.goto('http://withdraw.test/#unsubscribe='+capability)
  page.wait_for_selector('#link-withdrawal:visible')
  assert page.evaluate('location.hash')=='' and capability not in page.content()
  assert not attempts, 'GET/page load must never unsubscribe'
  assert not page.evaluate('localStorage.length || sessionStorage.length')
  page.locator('#confirm-withdrawal').click()
  page.wait_for_function('document.querySelector("#withdrawal-status").textContent.includes("could not be completed")')
  assert not page.locator('#confirm-withdrawal').is_disabled()
  page.locator('#confirm-withdrawal').click()
  page.wait_for_function('document.querySelector("#withdrawal-status").textContent.includes("request processed")')
  assert len(withdrawals)==1 and page.locator('#confirm-withdrawal').is_disabled()
  page.close()
 print('PASS: static mobile preview/terms/optional consent/progress; live Google mock SSE/204/auth; preference revision enrollment; pending-release guide; withdrawal; signout; no localStorage; no page errors; pending-enrollment signout race; withdrawal across reset; fragment scrubbing/explicit confirmation/retry without login; public same-origin SHA-pinned installation; invalid/stale metadata rejected.')
 b.close()
