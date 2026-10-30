#!/usr/bin/env python3
"""Synthetic read-after-write checks for reused filtered SQL snapshots.

The pinned server retains each requester's private snapshot while the source
database is unchanged. These checks prove reuse with X-Context-Snapshot-At
(unchanged on a cache hit), then require invitations, acceptance, new versions,
revocation and account disablement to change vault metadata visibility on the
very next read, with no rows leaking to unrelated requesters. Metadata and
ciphertext here are opaque synthetic strings.
"""
import argparse
import concurrent.futures
import json
import urllib.error
import urllib.request
from integration import server, ROOT

PASSWORD = 'SyntheticUserPassword123!'
TABLES = ('vaults', 'memberships', 'key_envelopes', 'documents', 'versions', 'version_chunks', 'invitations', 'audit_log',
          'identity_secrets')
RELEASE = json.loads((ROOT / 'pb_hooks/release.json').read_text())['release_id']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with server(args.binary, workspace_domain='example.com') as request:
        path = lambda table: '/api/collections/' + table + '/records'
        admin = request('POST', '/api/collections/_superusers/auth-with-password',
                        {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        ids, tokens = {}, {}
        for name in ('alice', 'bob', 'eve'):
            email = name + '@example.com'
            ids[name] = request('POST', path('users'), {'email': email, 'workspace_google_email': email, 'workspace_google_domain': 'example.com',
                                                        'name': name, 'password': PASSWORD, 'passwordConfirm': PASSWORD}, admin)['id']
            tokens[name] = request('POST', '/api/collections/users/auth-with-password', {'identity': email, 'password': PASSWORD})['token']

        def act(name, op, payload, expected=200):
            result = request('POST', path('vault_actions'), {'op': op, 'payload': payload}, tokens[name], expected)
            return result.get('result', result)

        def sql(query, name, expected=200):
            req = urllib.request.Request(request.base_url + '/api/context/query', data=json.dumps({'sql': query}).encode(), method='POST',
                                         headers={'Content-Type': 'application/json', 'Authorization': tokens[name],
                                                  'X-VaultContext-Release': RELEASE})
            try:
                with urllib.request.urlopen(req, timeout=25) as response:
                    status, raw, headers = response.status, response.read(), response.headers
            except urllib.error.HTTPError as error:
                status, raw, headers = error.code, error.read(), error.headers
            assert status in (expected if isinstance(expected, tuple) else (expected,)), (query, name, status, raw.decode())
            if status != 200:
                return None, None
            assert headers['X-Context-Scope'] == 'authorized-snapshot'
            result = json.loads(raw)
            assert not result['truncated']
            return result['rows'], headers['X-Context-Snapshot-At']

        counts = ' UNION ALL '.join([f"SELECT '{table}', count(*) FROM {table}" for table in TABLES] +
                                    ["SELECT 'active_memberships', count(*) FROM memberships WHERE active = 1"])

        def view(name):
            rows, at = sql(counts, name)
            return {table: count for table, count in rows if count}, at

        def warm(name):
            first, at = view(name)
            again, at2 = view(name)
            assert first == again and at == at2, ('expected a reused snapshot for an unchanged source', name)
            return first, at

        def fresh(name, before):
            result, at = view(name)
            assert at != before, ('a committed write must invalidate the reused snapshot', name)
            return result

        def stamps():
            return {name: warm(name)[1] for name in tokens}

        schema = request('GET', '/api/context/schema', token=tokens['alice'])
        assert schema['permissionModel'] == 'filtered-snapshot' and 'snapshot' not in schema, 'background snapshots must stay disabled'
        assert schema['snapshotLimits']['maxConcurrentPerRequester'] == 0, 'per-requester admission must stay disabled'

        for name in tokens:
            act(name, 'identity_init', {'public_key': 'synthetic-public-' + name, 'signing_key': 'synthetic-signing-' + name,
                                        'fingerprint': 'synthetic-fingerprint-' + name, 'key_bundle': 'encrypted-bundle'})
        vault, document = 'v' * 15, 'd' * 15
        act('alice', 'vault_create', {'id': vault, 'metadata': 'encrypted-title', 'envelope': 'alice-envelope'})
        save = {'vault': vault, 'document': document, 'version': 'a' * 15, 'expected_revision': 0, 'epoch': 1, 'metadata': 'encrypted-name',
                'manifest': 'encrypted-manifest', 'signature': 'signature', 'chunks': ['encrypted-binary-chunk']}
        act('alice', 'save', save)
        owner = warm('alice')[0]
        assert owner['vaults'] == owner['memberships'] == owner['documents'] == owner['versions'] == owner['version_chunks'] == 1
        outsider = {'identity_secrets': 1}
        assert warm('bob')[0] == outsider and warm('eve')[0] == outsider

        # A pending invitation reveals the invitee's own envelope and invitation, never vault metadata.
        before = stamps()
        invitation = act('alice', 'share', {'vault': vault, 'account': ids['bob'], 'role': 'reader', 'expected_revision': 1,
                                            'envelopes': [{'epoch': 1, 'envelope': 'bob-envelope'}]})
        assert fresh('bob', before['bob']) == dict(outsider, key_envelopes=1, invitations=1)
        assert fresh('eve', before['eve']) == outsider
        owner = fresh('alice', before['alice'])
        assert owner['invitations'] == 1 and owner['memberships'] == 2 and owner['active_memberships'] == 1, owner

        # Acceptance grants membership; the next read shows the vault's metadata to the new member.
        before = stamps()
        accepted = act('bob', 'accept', {'invitation': invitation['id']})
        member = fresh('bob', before['bob'])
        assert all(member.get(table) == owner.get(table) for table in ('vaults', 'documents', 'versions', 'version_chunks')), member
        assert member['active_memberships'] == 2 and member['key_envelopes'] == 1 and member['identity_secrets'] == 1
        assert fresh('alice', before['alice'])['active_memberships'] == 2
        assert fresh('eve', before['eve']) == outsider

        # A new version reaches every member's next read, and nobody else's.
        before = stamps()
        act('alice', 'save', dict(save, version='b' * 15, expected_revision=1))
        assert fresh('bob', before['bob'])['versions'] == 2
        assert fresh('alice', before['alice'])['versions'] == 2
        assert fresh('eve', before['eve']) == outsider

        # Concurrent reads from several sessions of one account are admitted (no per-requester 429).
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: view('bob')[0]['versions'], range(8)))
        assert results == [2] * 8

        # Revocation removes the cached member view at once, including key envelopes.
        before = stamps()
        act('alice', 'revoke', {'vault': vault, 'account': ids['bob'], 'expected_revision': accepted['revision']})
        assert fresh('bob', before['bob']) == dict(outsider, invitations=1)
        assert fresh('eve', before['eve']) == outsider
        assert fresh('alice', before['alice'])['active_memberships'] == 1

        # Disablement is enforced before any retained snapshot can be served.
        warm('eve')
        request('PATCH', path('users') + '/' + ids['eve'], {'disabled': True}, admin)
        sql(counts, 'eve', expected=(401, 403))
    print('Snapshot reuse read-after-write, membership grant/revocation, privacy and disablement checks passed')


if __name__ == '__main__':
    main()
