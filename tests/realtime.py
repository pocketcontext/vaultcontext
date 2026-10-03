#!/usr/bin/env python3
"""Private domain records never leak through PocketBase realtime subscriptions."""
import argparse
import json
import queue
import threading
import urllib.request
from integration import server

class Events:
    def __init__(self, request, token, collection):
        self.messages=queue.Queue()
        self.response=urllib.request.urlopen(request.base_url+'/api/realtime',timeout=8)
        def read():
            event='';data=[]
            try:
                for raw in self.response:
                    line=raw.decode().rstrip('\r\n')
                    if line.startswith('event:'):event=line[6:].strip()
                    elif line.startswith('data:'):data.append(line[5:].strip())
                    elif not line and data:
                        self.messages.put((event,json.loads('\n'.join(data))))
                        event='';data=[]
            except (OSError,ValueError):pass
        threading.Thread(target=read,daemon=True).start()
        event,data=self.messages.get(timeout=5)
        assert event=='PB_CONNECT'
        request('POST','/api/realtime',{'clientId':data['clientId'],'subscriptions':[collection+'/*']},token,204)
    def next(self,timeout=3):return self.messages.get(timeout=timeout)
    def quiet(self):
        try:raise AssertionError(self.next(.7))
        except queue.Empty:pass

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',required=True);a=p.parse_args()
    with server(a.binary) as request:
        admin=request('POST','/api/collections/_superusers/auth-with-password',{'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
        user=request('POST','/api/collections/users/records',{'email':'member@example.com','name':'Synthetic','password':'SyntheticUserPassword123!','passwordConfirm':'SyntheticUserPassword123!'},admin)
        token=request('POST','/api/collections/users/auth-with-password',{'identity':'member@example.com','password':'SyntheticUserPassword123!'})['token']
        # The superuser stream proves that a real create event was emitted.
        positive=Events(request,admin,'vaults');ordinary=Events(request,token,'vaults')
        def act(op,payload):return request('POST','/api/collections/vault_actions/records',{'op':op,'payload':payload},token)
        act('identity_init',{'public_key':'test-public','signing_key':'test-signing','fingerprint':'test-fingerprint','key_bundle':'test-ciphertext'})
        act('vault_create',{'id':'realtimevault01','metadata':'ciphertext','envelope':'ciphertext'})
        _,event=positive.next()
        assert event['action']=='create' and event['record']['id']=='realtimevault01'
        ordinary.quiet()
    print('VaultContext realtime isolation: PASS')
if __name__=='__main__':main()
