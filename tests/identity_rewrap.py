#!/usr/bin/env python3
"""Proof-of-key regression backported from demo 1164339; synthetic records only."""
import argparse
from integration import server
from vaultcontext_client import crypto, cli


def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',required=True);args=p.parse_args()
    with server(args.binary) as request:
        admin=request('POST','/api/collections/_superusers/auth-with-password',{'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
        user=request('POST','/api/collections/users/records',{'email':'synthetic@example.com','name':'Synthetic','password':'SyntheticPassword123!','passwordConfirm':'SyntheticPassword123!'},admin)
        account=user['id']
        token=request('POST','/api/collections/users/auth-with-password',{'identity':'synthetic@example.com','password':'SyntheticPassword123!'})['token']
        identity=crypto.generate_identity();pub=crypto.public_identity(identity)
        def action(op,payload,expected=200):
            return request('POST','/api/collections/vault_actions/records',{'op':op,'payload':payload},token,expected)
        action('identity_init',{'public_key':pub['enc_public'],'signing_key':pub['sign_public'],'fingerprint':crypto.fingerprint(pub),'key_bundle':cli.encode(crypto.wrap_identity(identity,'original synthetic passphrase',account))})
        original=request('POST','/api/context/query',{'sql':'SELECT key_bundle,revision FROM identity_secrets'},token)['rows']
        new=cli.encode(crypto.wrap_identity(identity,'new synthetic passphrase',account))
        payload={'key_bundle':new,'expected_revision':1}
        action('identity_rewrap',payload,403)
        signed=dict(payload,account=account,purpose='identity-rewrap')
        signature=crypto.sign_manifest(identity,signed)
        action('identity_rewrap',dict(payload,signature=crypto.sign_manifest(crypto.generate_identity(),signed)),403)
        action('identity_rewrap',dict(payload,key_bundle='GARBAGE',signature=signature),403)
        action('identity_rewrap',dict(payload,signature=crypto.sign_manifest(identity,dict(signed,account='x'*15))),403)
        assert request('POST','/api/context/query',{'sql':'SELECT key_bundle,revision FROM identity_secrets'},token)['rows']==original
        assert request('POST','/api/context/query',{'sql':"SELECT id FROM audit_log WHERE action='identity_rewrap'"},token)['rows']==[]
        action('identity_rewrap',dict(payload,signature=signature))
        action('identity_rewrap',dict(payload,signature=signature),409)
        result=request('POST','/api/context/query',{'sql':'SELECT key_bundle,revision FROM identity_secrets'},token)
        assert result['rows']==[[new,2]],result
        assert crypto.unwrap_identity(__import__('json').loads(new),'new synthetic passphrase',account)==identity
        events=request('POST','/api/context/query',{'sql':"SELECT actor,action,target FROM audit_log WHERE action='identity_rewrap'"},token)
        assert events['rows']==[[account,'identity_rewrap',account]],events
        request('POST','/api/collections/users/records',{'email':'other@example.com','name':'Other','password':'SyntheticPassword123!','passwordConfirm':'SyntheticPassword123!'},admin)
        other=request('POST','/api/collections/users/auth-with-password',{'identity':'other@example.com','password':'SyntheticPassword123!'})['token']
        assert request('POST','/api/context/query',{'sql':"SELECT id FROM audit_log WHERE action='identity_rewrap'"},other)['rows']==[]
    print('Signed identity replacement: PASS')


if __name__=='__main__':main()
