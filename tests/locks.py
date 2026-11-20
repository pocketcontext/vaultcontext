#!/usr/bin/env python3
"""Vault-level pessimistic lock: races, fencing, membership and migration checks."""
import argparse
import concurrent.futures
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from integration import ROOT, server  # noqa: E402

PASSWORD = 'SyntheticUserPassword123!'


def setup(request):
    path = lambda t: '/api/collections/' + t + '/records'
    admin = request('POST', '/api/collections/_superusers/auth-with-password',
                    {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
    accounts = {}
    for name in ['alice', 'bob', 'carol', 'dave']:
        u = request('POST', path('users'), {'email': name + '@example.com', 'workspace_google_email': name + '@example.com',
                                            'workspace_google_domain': 'example.com', 'name': name,
                                            'password': PASSWORD, 'passwordConfirm': PASSWORD}, admin)
        t = request('POST', '/api/collections/users/auth-with-password', {'identity': name + '@example.com', 'password': PASSWORD})['token']
        accounts[name] = (u['id'], t)

    def act(token, op, payload, expected=200):
        r = request('POST', path('vault_actions'), {'op': op, 'payload': payload}, token, expected)
        return r.get('result', r)

    def query(token, sql):
        r = request('POST', '/api/context/query', {'sql': sql}, token)
        return [dict(zip(r['columns'], row)) for row in r['rows']]

    from vaultcontext_client import crypto
    for uid, token in accounts.values():
        public = crypto.public_identity(crypto.generate_identity())
        act(token, 'identity_init', {'public_key': public['enc_public'], 'signing_key': public['sign_public'],
                                     'fingerprint': crypto.fingerprint(public), 'key_bundle': 'encrypted-bundle'})
    return admin, accounts, act, query, path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with server(args.binary, workspace_domain='example.com') as request:
        admin, accounts, act, query, path = setup(request)
        (alice, at), (bob, bt), (carol, ct), (dave, dt) = (accounts[n] for n in ('alice', 'bob', 'carol', 'dave'))
        v = 'lockvault000001'
        act(at, 'vault_create', {'id': v, 'metadata': 'encrypted-title', 'envelope': 'alice-envelope'})
        vault = lambda: query(at, f"SELECT * FROM vaults WHERE id='{v}'")[0]
        lock = lambda: (query(at, f"SELECT * FROM locks WHERE vault='{v}'") or [None])[0]
        assert vault()['lock_policy'] == 'none'
        versions = iter(f'ver{n:012d}' for n in range(1, 1000))

        def save(token, doc, revision, expected=200, **extra):
            body = {'vault': v, 'document': doc, 'version': next(versions), 'expected_revision': revision,
                    'epoch': vault()['epoch'], 'metadata': 'encrypted-name', 'manifest': 'encrypted-manifest',
                    'signature': 'signature', 'chunks': ['encrypted-chunk-a', 'encrypted-chunk-b']}
            body.update(extra)
            return act(token, 'save', body, expected)

        # Before any lock, unfenced saves keep working (back-compat).
        save(at, 'docstate0000001', 0)
        save(at, 'docenvrc0000001', 0)
        # Members: bob editor (active), carol reader (active), dave invited reader (pending).
        for who, role in ((bob, 'editor'), (carol, 'reader')):
            inv = act(at, 'share', {'vault': v, 'account': who, 'role': role, 'expected_revision': vault()['revision'],
                                    'envelopes': [{'epoch': 1, 'envelope': 'envelope'}]})
            act(bt if who == bob else ct, 'accept', {'invitation': inv['id']})
        dave_invitation = act(at, 'share', {'vault': v, 'account': dave, 'role': 'reader', 'expected_revision': vault()['revision'],
                                            'envelopes': [{'epoch': 1, 'envelope': 'envelope'}]})

        # Readers cannot lock; invalid arguments are rejected before any state change.
        act(ct, 'lock_acquire', {'vault': v}, 403)
        for bad in ({'ttl_seconds': 29}, {'ttl_seconds': 3601}, {'on_mismatch': 'merge'}, {'info': {'x': 'y' * 3000}},
                    {'info': {'x':'界'*800}}, {'force': True}, {'force': True, 'observed_generation': 0},
                    {'local': {'documents': [{'id': 'short'}]}}):
            act(at, 'lock_acquire', dict(bad, vault=v), 400)
        assert lock() is None

        # Two concurrent acquires: exactly one wins; the loser sees the label.
        def acquire(token, label):
            return request('POST', path('vault_actions'), {'op': 'lock_acquire', 'payload': {
                'vault': v, 'info': {'label': label, 'command': 'converge'}, 'request_id': 'req-' + label.split('@')[0]}}, token, (200, 409))
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda x: acquire(*x), [(at, 'alice@box'), (bt, 'bob@box')]))
        winners = [r['result'] for r in results if 'result' in r]
        losers = [r for r in results if 'result' not in r]
        assert len(winners) == 1 and len(losers) == 1, results
        assert losers[0]['data']['code'] == 'lock_held'
        held = losers[0]['data']
        assert held['info']['label'] in ('alice@box', 'bob@box') and held['generation'] == 1
        assert held['retry_after'] >= 1 and held['expires_at'] and 'lease_id' not in held
        first = winners[0]
        assert first['generation'] == 1 and len(first['lease_id']) == 15 and first['local_status'] == 'unchecked'
        holder_token = bt if held['info']['label'] == 'bob@box' else at
        other_token = bt if holder_token == at else at
        # Manifest lists every document with ciphertext chunk hashes in order.
        assert [d['id'] for d in first['documents']] == ['docenvrc0000001', 'docstate0000001']
        assert all(d['chunk_count'] == 2 and len(d['chunks']) == 2 and len(d['chunks'][0]['sha256']) == 64 for d in first['documents'])
        assert first['vault']['lock_policy'] == 'required' and vault()['lock_policy'] == 'required'
        fence = {'generation': first['generation'], 'lease_id': first['lease_id']}

        # request_id replay returns the same lease; a different request is refused NOWAIT.
        mine = 'req-alice' if holder_token == at else 'req-bob'
        original = {'vault': v, 'request_id': mine, 'info': held['info']}
        replay = act(holder_token, 'lock_acquire', original)
        assert replay['lease_id'] == first['lease_id'] and replay['generation'] == 1
        assert act(holder_token, 'lock_acquire', {'vault': v}, 409)['data']['code'] == 'lock_held'

        # Protected vault: unfenced saves fail; the holder's fence succeeds; another user's copy is stale.
        assert save(holder_token, 'docstate0000001', 1, 409)['data']['code'] == 'lock_required'
        save(holder_token, 'docstate0000001', 1, fence=fence)
        replay = act(holder_token, 'lock_acquire', original)
        assert replay['documents'] == first['documents']
        assert act(holder_token, 'lock_acquire', dict(original, local={'documents': []}), 409)['data']['code'] == 'request_changed'
        assert save(other_token, 'docstate0000001', 2, 409, fence=fence)['data']['code'] == 'stale_fence'
        assert save(holder_token, 'docstate0000001', 1, 409, fence=fence)['data']['code'] == 'revision_conflict'
        save(holder_token, 'docstate0000001', 2, 400, fence={'generation': 'x'})

        # Membership changes wait for the lock; revoke stays possible (tested below).
        assert act(at, 'share', {'vault': v, 'account': dave, 'role': 'editor', 'expected_revision': vault()['revision'],
                                 'envelopes': []}, 409)['data']['code'] == 'lock_held'
        assert act(dt, 'accept', {'invitation': dave_invitation['id']}, 409)['data'] == {'code':'lock_held'}
        assert act(at, 'archive', {'vault': v, 'document': 'docenvrc0000001', 'expected_revision': 1,
                                   'expected_archive_revision': 0}, 409)['data']['code'] == 'lock_held'
        assert act(at, 'vault_archive', {'vault': v, 'expected_revision': vault()['revision'],
                                         'expected_archive_revision': 0}, 409)['data']['code'] == 'lock_held'
        assert act(at, 'lock_policy_clear', {'vault': v, 'expected_revision': vault()['revision']}, 409)['data']['code'] == 'lock_held'

        # Renew is not audited and stores progress; members read lock state through SQL.
        audits = len(query(at, 'SELECT * FROM audit_log'))
        renewed = act(holder_token, 'lock_renew', dict(fence, vault=v, progress='applications', ttl_seconds=600))
        assert renewed['late'] is False and len(query(at, 'SELECT * FROM audit_log')) == audits
        assert lock()['progress'] == 'applications' and lock()['ttl_seconds'] == 600
        assert query(ct, 'SELECT holder FROM locks')[0]['holder'] in (alice, bob)
        assert query(dt, 'SELECT * FROM locks') == []
        for token in (holder_token, ct):
            assert not {'lease_id','request_id','grant','request_hash'}.intersection(query(token,'SELECT * FROM locks')[0])

        # Force: editors cannot; stale generation is refused; matching generation breaks+acquires atomically.
        assert act(bt, 'lock_acquire', {'vault': v, 'force': True, 'observed_generation': 1, 'reason': 'x'}, 403)
        assert act(at, 'lock_acquire', {'vault': v, 'force': True, 'observed_generation': 7, 'reason': 'crash'}, 409)['data']['code'] == 'generation_changed'
        before = query(at, 'SELECT * FROM audit_log ORDER BY id')
        assert act(at, 'lock_acquire', {'vault': v, 'force': True, 'observed_generation': 1, 'reason': 'stale local',
                                        'local': {'documents': []}}, 409)['data']['code'] == 'local_mismatch'
        assert lock()['generation'] == 1 and lock()['state'] == 'held'
        assert query(at, 'SELECT * FROM audit_log ORDER BY id') == before
        act(holder_token, 'lock_renew', dict(fence, vault=v))
        forced = act(at, 'lock_acquire', {'vault': v, 'force': True, 'observed_generation': 1, 'reason': 'holder crashed',
                                          'info': {'label': 'alice-recovery'}})
        assert forced['generation'] == 3 and forced['previous']['clean'] is False and forced['previous']['generation'] == 1
        assert act(holder_token, 'lock_renew', dict(fence, vault=v), 409)['data']['code'] == 'lock_lost'
        assert act(holder_token, 'lock_release', dict(fence, vault=v, clean=True), 409)['data']['code'] == 'lock_lost'
        assert save(holder_token, 'docstate0000001', 2, 409, fence=fence)['data']['code'] == 'stale_fence'
        fence = {'generation': forced['generation'], 'lease_id': forced['lease_id']}
        actions = [r['action'] for r in query(at, 'SELECT action FROM audit_log ORDER BY created, id')]
        assert {'lock_acquire', 'lock_policy_required', 'lock_break', 'lock_force_acquire'} <= set(actions)
        assert 'lock_renew' not in actions
        assert query(at, "SELECT reason,generation FROM audit_log WHERE action='lock_break'") == [{'reason':'holder crashed','generation':1}]

        # Break: stale generation refused; matching generation frees the lock and fences the old lease.
        assert act(at, 'lock_break', {'vault': v, 'observed_generation': 1, 'reason': 'x'}, 409)['data']['code'] == 'generation_changed'
        act(bt, 'lock_break', {'vault': v, 'observed_generation': 3, 'reason': 'x'}, 403)
        act(at, 'lock_break', {'vault': v, 'observed_generation': 3}, 400)
        broken = act(at, 'lock_break', {'vault': v, 'observed_generation': 3, 'reason': 'coordinated with bob'})
        assert broken == {'generation': 4, 'state': 'broken', 'broken': True}
        assert lock()['state'] == 'broken' and lock()['break_reason'] == 'coordinated with bob' and lock()['broken_by'] == alice
        assert save(at, 'docstate0000001', 2, 409, fence=fence)['data']['code'] == 'stale_fence'
        assert act(at, 'lock_break', {'vault': v, 'observed_generation': 4, 'reason': 'again'})['broken'] is False

        # Local manifest comparison. Documents: state rev 2, envrc rev 1.
        docs = {d['id']: d for d in query(at, f"SELECT * FROM documents WHERE vault='{v}'")}
        local = lambda **over: {'documents': [
            {'id': i, 'revision': over.get(i, (d['revision'], d['current_version']))[0], 'version': over.get(i, (d['revision'], d['current_version']))[1]}
            for i, d in docs.items() if i not in over.get('drop', ())]}
        stale = local(docstate0000001=(1, 'ver000000000001'))
        refused = act(bt, 'lock_acquire', {'vault': v, 'local': stale}, 409)['data']
        assert refused['code'] == 'local_mismatch' and refused['local_status'] == 'stale'
        assert refused['local_details']['stale'] == ['docstate0000001'] and len(refused['remote']['documents']) == 2
        assert lock()['state'] == 'broken' and lock()['generation'] == 4  # not taken
        assert act(bt, 'lock_acquire', {'vault': v, 'local': local(drop=('docenvrc0000001',))}, 409)['data']['local_status'] == 'extra_remote'
        missing = local()
        missing['documents'].append({'id': 'docgone00000001', 'revision': 1, 'version': 'vergone00000001'})
        assert act(bt, 'lock_acquire', {'vault': v, 'local': missing}, 409)['data']['local_status'] == 'missing_remote'
        assert act(bt, 'lock_acquire', {'vault': v, 'local': local(docstate0000001=(2, 'verdivergent001'))}, 409)['data']['local_status'] == 'diverged'
        granted = act(bt, 'lock_acquire', {'vault': v, 'local': stale, 'on_mismatch': 'lock', 'info': {'label': 'bob-restore'}})
        assert granted['local_status'] == 'stale' and granted['generation'] == 5
        assert granted['previous']['state'] == 'broken'
        bob_fence = {'generation': 5, 'lease_id': granted['lease_id']}
        release = act(bt, 'lock_release', dict(bob_fence, vault=v, clean=True, progress='done'))
        assert release['released'] is True and {d['id'] for d in release['documents']} == set(docs)
        assert act(bt, 'lock_release', dict(bob_fence, vault=v, clean=True)) == release  # idempotent
        assert act(bt, 'lock_release', dict(bob_fence, vault=v, clean=True, lease_id='wronglease00001'), 409)['data']['code'] == 'lock_lost'
        assert lock()['state'] == 'released' and lock()['clean'] in (True, 1)
        matched = act(at, 'lock_acquire', {'vault': v, 'local': local()})
        assert matched['local_status'] == 'match' and matched['previous']['clean'] is True
        alice_fence = {'generation': matched['generation'], 'lease_id': matched['lease_id']}

        # Late renew (expired, nobody took over) and expiry takeover.
        row_id = lock()['id']
        request('PATCH', path('locks') + '/' + row_id, {'expires_at': '2000-01-01T00:00:00.000Z'}, admin)
        save(at, 'docenvrc0000001', 1, fence=alice_fence)  # late but not taken
        assert act(at, 'lock_renew', dict(alice_fence, vault=v))['late'] is True
        request('PATCH', path('locks') + '/' + row_id, {'expires_at': '2000-01-01T00:00:00.000Z'}, admin)
        takeover = act(bt, 'lock_acquire', {'vault': v})
        assert takeover['previous']['clean'] is False and takeover['generation'] == alice_fence['generation'] + 2
        assert act(at, 'lock_renew', dict(alice_fence, vault=v), 409)['data']['code'] == 'lock_lost'
        assert save(at, 'docenvrc0000001', 2, 409, fence=alice_fence)['data']['code'] == 'stale_fence'
        bob_fence = {'generation': takeover['generation'], 'lease_id': takeover['lease_id']}

        # Revoke while held freezes the vault; the holder may still renew and release.
        act(at, 'revoke', {'vault': v, 'account': carol, 'expected_revision': vault()['revision']})
        assert vault()['frozen'] in (True, 1)
        act(bt, 'lock_renew', dict(bob_fence, vault=v))
        act(bt, 'lock_release', dict(bob_fence, vault=v, clean=False))
        assert act(bt, 'lock_acquire', {'vault': v}, 409)['data']['code'] == 'vault_frozen'
        rotate = lambda: act(at, 'rotate', {'vault': v, 'expected_revision': vault()['revision'], 'epoch': vault()['epoch'] + 1,
                                            'envelopes': [{'account': m['account'], 'envelope': 'rotated'} for m in
                                                          query(at, f"SELECT account FROM memberships WHERE vault='{v}' AND active=1")]})
        rotate()
        # Rotation while held invalidates the lock.
        held = act(bt, 'lock_acquire', {'vault': v})
        act(at, 'revoke', {'vault': v, 'account': dave, 'expected_revision': vault()['revision']})
        rotate()
        assert lock()['state'] == 'broken' and lock()['break_reason'] == 'key_rotation'
        assert act(bt, 'lock_renew', {'vault': v, 'generation': held['generation'], 'lease_id': held['lease_id']}, 409)['data']['code'] == 'lock_lost'
        assert query(at, "SELECT generation FROM audit_log WHERE action='lock_break' AND reason='key_rotation'") == [{'generation':held['generation']}]
        held = act(bt, 'lock_acquire', {'vault':v})
        request('PATCH', path('locks') + '/' + lock()['id'], {'expires_at':'2000-01-01T00:00:00.000Z'}, admin)
        act(at, 'archive', {'vault': v, 'document':'docenvrc0000001','expected_revision':2,'expected_archive_revision':0})
        assert lock()['break_reason'] == 'expired_view_changed'
        assert act(bt,'lock_renew',{'vault':v,'generation':held['generation'],'lease_id':held['lease_id']},409)['data']['code']=='lock_lost'
        held = act(bt, 'lock_acquire', {'vault':v})
        request('PATCH', path('users')+'/'+bob, {'disabled':True}, admin)
        act(bt,'lock_renew',{'vault':v,'generation':held['generation'],'lease_id':held['lease_id']},(401,403))
        request('PATCH', path('users')+'/'+bob, {'disabled':False}, admin)
        bt=request('POST', '/api/collections/users/auth-with-password', {'identity':'bob@example.com','password':PASSWORD})['token']
        act(at, 'revoke', {'vault':v,'account':bob,'expected_revision':vault()['revision']})
        act(bt,'lock_renew',{'vault':v,'generation':held['generation'],'lease_id':held['lease_id']},403)
        rotate()

        # The owner can clear the policy when no lock is held; unfenced saves then work again.
        act(at, 'lock_policy_clear', {'vault': v, 'expected_revision': vault()['revision'] - 1}, 409)
        act(bt, 'lock_policy_clear', {'vault': v, 'expected_revision': vault()['revision']}, 403)
        assert act(at, 'lock_policy_clear', {'vault': v, 'expected_revision': vault()['revision']})['lock_policy'] == 'none'
        save(at, 'docnew000000001', 0)
        assert 'lock_policy_clear' in [r['action'] for r in query(at, 'SELECT action FROM audit_log')]
        # Archived vaults cannot be locked.
        act(at, 'vault_archive', {'vault': v, 'expected_revision': vault()['revision'], 'expected_archive_revision': 0})
        assert act(at, 'lock_acquire', {'vault': v}, 409)['data']['code'] == 'vault_archived'
        act(at,'vault_unarchive',{'vault':v,'expected_revision':vault()['revision'],'expected_archive_revision':1})
        old=act(at,'lock_acquire',{'vault':v})
        request('PATCH', path('locks')+'/'+lock()['id'],{'expires_at':'2000-01-01T00:00:00.000Z'},admin)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            take=pool.submit(act,at,'lock_acquire',{'vault':v})
            release=pool.submit(act,at,'lock_break',{'vault':v,'observed_generation':old['generation'],'reason':'race'},(200,409))
        current=take.result()
        assert release.result().get('broken') or release.result()['data']['code']=='generation_changed'
        assert lock()['state']=='held' and lock()['generation']==current['generation']
        act(at,'lock_renew',{'vault':v,'generation':current['generation'],'lease_id':current['lease_id']})

    # Migration: existing vaults gain lock_policy 'none'.
    with tempfile.TemporaryDirectory(prefix='vaultcontext-lockmig-') as tmp:
        old = Path(tmp) / 'migrations'
        shutil.copytree(ROOT / 'pb_migrations', old)
        (old / '1790300600_vault_locks.js').unlink()
        (old / '1790300700_lock_audit.js').unlink()
        data = Path(tmp) / 'isolated-database'
        with server(args.binary, migrations=old, data_dir=data, workspace_domain='example.com', context_config=old_context()) as request:
            _, accounts, act, query, _ = setup(request)
            act(accounts['alice'][1], 'vault_create', {'id': 'oldvault0000001', 'metadata': 'm', 'envelope': 'e'})
        # Exercise both the first policy backfill and a lease issued by the original lock schema.
        migration_name = '1790300600_vault_locks.js'
        shutil.copy2(ROOT / 'pb_migrations' / migration_name, old / migration_name)
        config = old_context()
        config['tables']['vaults'].append('lock_policy')
        with server(args.binary, migrations=old, data_dir=data, workspace_domain='example.com', context_config=config) as request:
            admin = request('POST','/api/collections/_superusers/auth-with-password',
                            {'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
            request('POST','/api/collections/locks/records',
                    {'vault':'oldvault0000001','holder':accounts['alice'][0],'state':'held','generation':3,
                     'lease_id':'oldlease0000001','request_id':'old-request'},admin)
        recovered = Path(tmp) / 'offline-recovery'
        shutil.copytree(data, recovered)
        module = importlib.util.spec_from_file_location('entrypoint', ROOT/'docker/entrypoint.py')
        entrypoint = importlib.util.module_from_spec(module)
        module.loader.exec_module(entrypoint)
        entrypoint.SERVER, entrypoint.APP = str(Path(args.binary).resolve()), ROOT
        entrypoint.retire_restored_locks(recovered)
        with server(args.binary, data_dir=recovered, workspace_domain='example.com') as request:
            token = request('POST','/api/collections/users/auth-with-password',{'identity':'alice@example.com','password':PASSWORD})['token']
            query = lambda sql: request('POST','/api/context/query',{'sql':sql},token)['rows']
            assert query('SELECT state,generation FROM locks') == [['broken',4]]
            assert query("SELECT generation,reason FROM audit_log WHERE action='lock_break'") == [[3,'database_restore']]
        with server(args.binary, data_dir=data, workspace_domain='example.com') as request:
            token = request('POST', '/api/collections/users/auth-with-password', {'identity': 'alice@example.com', 'password': PASSWORD})['token']
            r = request('POST', '/api/context/query', {'sql': 'SELECT lock_policy FROM vaults'}, token)
            assert r['rows'] == [['none']], r
            assert request('POST','/api/context/query',{'sql':'SELECT state,generation FROM locks'},token)['rows'] == [['broken',4]]
            assert request('POST','/api/context/query',{'sql':"SELECT generation,reason FROM audit_log WHERE action='lock_break'"},token)['rows'] == [[3,'lock_schema_upgrade']]
    print('lock checks passed')


def old_context():
    import json
    config = json.loads((ROOT / 'pocketcontext.json').read_text())
    config['tables'].pop('locks')
    config['snapshot']['filters'].pop('locks')
    config['tables']['vaults'].remove('lock_policy')
    config['tables']['audit_log'].remove('reason')
    config['tables']['audit_log'].remove('generation')
    return config


if __name__ == '__main__':
    main()
