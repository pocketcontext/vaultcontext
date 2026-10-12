"""Vault lifecycle checks used by the isolated HTTP integration suite."""
import concurrent.futures


def run(request, accounts):
    (owner, ot), (editor, et), (reader, rt) = accounts
    path = lambda table: '/api/collections/' + table + '/records'

    def act(token, op, payload, expected=200):
        result = request('POST', path('vault_actions'), {'op': op, 'payload': payload}, token, expected)
        return result.get('result', result)

    def query(token, sql):
        result = request('POST', '/api/context/query', {'sql': sql}, token)
        return [dict(zip(result['columns'], row)) for row in result['rows']]

    vault = 'vaultarchive001'
    document = 'vaultarchdoc001'
    act(ot, 'vault_create', {'id': vault, 'metadata': 'synthetic-ciphertext', 'envelope': 'owner-envelope'})

    def state():
        return query(ot, f"SELECT * FROM vaults WHERE id='{vault}'")[0]

    def transition(op, token=ot, expected=200, **overrides):
        current = state()
        payload = {'vault': vault, 'expected_revision': current['revision'],
                   'expected_archive_revision': current['archive_revision']}
        payload.update(overrides)
        return act(token, op, payload, expected)

    def events():
        return query(ot, f"SELECT * FROM audit_log WHERE vault='{vault}'")

    def invite(account, role):
        return act(ot, 'share', {'vault': vault, 'account': account, 'role': role,
                   'expected_revision': state()['revision'], 'envelopes': [{'epoch': 1, 'envelope': 'synthetic-envelope'}]})

    save = {'vault': vault, 'document': document, 'version': 'vaultarchver001',
            'expected_revision': 0, 'epoch': 1, 'metadata': 'synthetic-encrypted-name',
            'manifest': 'synthetic-manifest', 'signature': 'synthetic-signature', 'chunks': ['synthetic-ciphertext']}
    act(ot, 'save', save)
    editor_invite = invite(editor, 'editor')
    act(et, 'accept', {'invitation': editor_invite['id']})
    reader_invite = invite(reader, 'reader')
    # A pending invitation grants no vault visibility and no archive authority.
    transition('vault_archive', rt, 403)
    assert query(rt, f"SELECT * FROM vaults WHERE id='{vault}'") == []
    transition('vault_archive', et, 403)
    transition('vault_unarchive', et, 403)
    transition('vault_archive', expected=409, expected_revision=0)
    transition('vault_archive', expected=409, expected_archive_revision=1)
    before = state()
    documents = query(ot, f"SELECT * FROM documents WHERE vault='{vault}'")
    versions = query(ot, f"SELECT * FROM versions WHERE vault='{vault}'")
    archived = transition('vault_archive')
    assert archived['archived'] is True and archived['archive_revision'] == 1
    assert archived['revision'] == before['revision'] + 1
    count = len(events())
    assert transition('vault_archive') == archived
    assert len(events()) == count
    assert sum(event['action'] == 'vault_archive' for event in events()) == 1
    transition('vault_unarchive', expected=409, expected_revision=before['revision'])
    act(rt, 'accept', {'invitation': reader_invite['id']}, 409)
    assert query(rt, f"SELECT * FROM vaults WHERE id='{vault}'") == []
    for token in (ot, et):
        act(token, 'save', dict(save, document='vaultarchdoc002', version='vaultarchver002', expected_vault_archive_revision=1), 409)
        act(token, 'save', dict(save, version='vaultarchver002', expected_revision=1, expected_vault_archive_revision=1), 409)
        for op in ('archive', 'unarchive'):
            act(token, op, {'vault': vault, 'document': document, 'expected_revision': 1, 'expected_archive_revision': 0}, 409)
    # Even an otherwise invalid new invitation fails at the archived-vault guard.
    act(ot, 'share', {'vault': vault, 'account': reader, 'role': 'reader',
                     'expected_revision': state()['revision'], 'envelopes': []}, 409)
    assert query(ot, f"SELECT * FROM documents WHERE vault='{vault}'") == documents
    assert query(et, f"SELECT * FROM versions WHERE vault='{vault}'") == versions
    chunk = query(et, f"SELECT * FROM version_chunks WHERE vault='{vault}'")[0]
    file_token = request('POST', '/api/files/token', {}, et)['token']
    file_path = '/api/files/version_chunks/' + chunk['id'] + '/' + chunk['ciphertext'] + '?token=' + file_token
    assert request('GET', file_path) == b'synthetic-ciphertext'
    active = transition('vault_unarchive')
    assert active['archive_revision'] == 2 and active['archived'] is False
    count = len(events())
    assert transition('vault_unarchive') == active
    assert len(events()) == count
    # Archive/unarchive ABA invalidates both omitted and explicitly stale save markers.
    for marker in ({}, {'expected_vault_archive_revision': 0}, {'expected_vault_archive_revision': 1}):
        act(et, 'save', dict(save, version='vaultarchver002', expected_revision=1, **marker), 409)
        act(et, 'save', dict(save, document='vaultarchdoc002', version='vaultarchver002', **marker), 409)
    act(et, 'save', dict(save, version='vaultarchver002', expected_revision=1, expected_vault_archive_revision=2))
    act(rt, 'accept', {'invitation': reader_invite['id']})
    transition('vault_archive', rt, 403)
    transition('vault_unarchive', rt, 403)
    # Document lifecycle remains independent of vault lifecycle.
    act(et, 'archive', {'vault': vault, 'document': document, 'expected_revision': 2, 'expected_archive_revision': 0})
    transition('vault_archive')
    assert query(rt, f"SELECT archived FROM documents WHERE id='{document}'")[0]['archived'] == 1
    assert len(query(rt, f"SELECT * FROM versions WHERE vault='{vault}'")) == 2
    # Security maintenance still works, and frozen/archived state are independent.
    act(ot, 'revoke', {'vault': vault, 'account': editor, 'expected_revision': state()['revision']})
    assert state()['archived'] and state()['frozen']
    request('GET', file_path, expected=(401, 403, 404))
    transition('vault_unarchive')
    assert state()['frozen'] and not state()['archived']
    transition('vault_archive')
    act(ot, 'rotate', {'vault': vault, 'expected_revision': state()['revision'], 'epoch': 2,
                      'envelopes': [{'account': owner, 'envelope': 'owner-new'}, {'account': reader, 'envelope': 'reader-new'}]})
    assert state()['archived'] and not state()['frozen']
    transition('vault_unarchive')
    assert query(ot, f"SELECT archived FROM documents WHERE id='{document}'")[0]['archived'] == 1
    # Concurrent archive requests transition and audit once, with one stale rejection.
    current = state()
    payload = {'vault': vault, 'expected_revision': current['revision'], 'expected_archive_revision': current['archive_revision']}
    count = len(events())
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: act(ot, 'vault_archive', payload, (200, 409)), range(2)))
    assert sum('id' in result for result in results) == 1, results
    assert len(events()) == count + 1
    transition('vault_unarchive')
    # Saves may linearize before archive, but can never publish after it succeeds.
    current = state()
    fresh = dict(save, document='vaultarchdoc003', version='vaultarchver003', epoch=2,
                 expected_vault_archive_revision=current['archive_revision'])
    payload = {'vault': vault, 'expected_revision': current['revision'], 'expected_archive_revision': current['archive_revision']}
    def race(op):
        return act(ot, op, payload if op == 'vault_archive' else fresh, (200, 409))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race, ('vault_archive', 'save')))
    assert results[0]['archived'] is True
    assert state()['archived']
    act(ot, 'save', dict(fresh, document='vaultarchdoc004', version='vaultarchver004'), 409)
    assert len(query(ot, "SELECT * FROM versions WHERE id='vaultarchver003'")) == int('version' in results[1])
    # An audit failure atomically rolls back the vault transition and both revisions.
    rollback = 'auditfailure003'
    act(ot, 'vault_create', {'id': rollback, 'metadata': 'synthetic-ciphertext', 'envelope': 'synthetic-envelope'})
    before = query(ot, f"SELECT * FROM vaults WHERE id='{rollback}'")[0]
    count = len(query(ot, f"SELECT * FROM audit_log WHERE vault='{rollback}'"))
    act(ot, 'vault_archive', {'vault': rollback, 'expected_revision': 1, 'expected_archive_revision': 0}, 400)
    assert query(ot, f"SELECT * FROM vaults WHERE id='{rollback}'")[0] == before
    assert len(query(ot, f"SELECT * FROM audit_log WHERE vault='{rollback}'")) == count
