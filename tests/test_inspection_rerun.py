"""자동 검사를 다시 실행해도 새 검사 사본이 지워지지 않는다 (이전엔 같은 파일 이름이라 새 사본까지 삭제돼 심사 통과가 500)."""
import base64
import os
from contextlib import contextmanager
from types import SimpleNamespace

for _k in ('DATABASE_URL', 'OIDC_DISCOVERY_URL', 'OIDC_CLIENT_SECRET', 'APP_BASE_URL'):
    os.environ.setdefault(_k, 'http://test')

from app import db, inspection, storage  # noqa: E402

FID = 'eeeeeeee-0000-4000-8000-000000000001'


def test_rerun_keeps_new_masked_copy(monkeypatch):
    files, state = {'orig': b'\xff\xd8\xffPHOTO'}, {'row': None}
    monkeypatch.setattr(storage, 'put', lambda k, d: files.__setitem__(k, d))
    monkeypatch.setattr(storage, 'get', lambda k: files[k])
    monkeypatch.setattr(storage, 'delete', lambda k: files.pop(k, None))

    class Conn:
        def execute(self, sql, params=()):
            if 'FROM evidence_files e JOIN members' in sql:
                return SimpleNamespace(fetchone=lambda: {'file_id': FID, 'kind': 'photo', 'storage_key': 'orig',
                                                         'status': 'submitted', 'name': 'n', 'birth_date': None})
            if 'SELECT fields_key, masked_key FROM evidence_inspections' in sql:
                return SimpleNamespace(fetchone=lambda: state['row'])
            if sql.strip().startswith('INSERT INTO evidence_inspections'):
                state['row'] = {'fields_key': params[7], 'masked_key': params[8]}
            return SimpleNamespace(fetchone=lambda: None)

    @contextmanager
    def connection():
        yield Conn()
    monkeypatch.setattr(db, 'connection', connection)
    jpeg = base64.b64encode(b'\xff\xd8\xffCLEAN').decode()
    monkeypatch.setattr(inspection, '_call', lambda data, kind: {
        'version': 't', 'photo': {'metadata_removed': True}, 'masked': {'data_base64': jpeg, 'media_type': 'image/jpeg'}})
    inspection.run(FID)
    first = dict(state['row'])
    inspection.run(FID)
    second = state['row']
    assert second['masked_key'] != first['masked_key']
    assert files[second['masked_key']] == b'\xff\xd8\xffCLEAN'          # 새 사본은 남아 있음
    assert first['masked_key'] not in files and first['fields_key'] not in files   # 이전 사본은 지워짐
