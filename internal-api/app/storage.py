"""암호화 파일 저장소 (evidence-storage).

- 증빙 원본과 관리자 내보내기 결과를 AES-256-GCM 암호문으로만 저장한다.
- 키는 Docker secret 파일에서 읽고 코드·DB 에 두지 않는다. DB 에는 key_id(키 지문)만 남긴다.
- 파일 이름은 서버가 만든 UUID 뿐이다 (사용자가 보낸 파일 이름·경로는 쓰지 않음).
- 연관 데이터(AAD)에 저장 키를 넣어, 암호문을 다른 파일 자리로 옮겨 바꿔치기하면 복호화가 실패한다.
"""
import base64
import hashlib
import os
import threading
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings

_NONCE = 12
_lock = threading.Lock()


@lru_cache
def _key() -> tuple[bytes, str]:
    raw = Path(get_settings().evidence_key_path).read_text(encoding="ascii").strip()
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("증빙 암호화 키는 32바이트(base64)여야 합니다")
    return key, "k-" + hashlib.sha256(key).hexdigest()[:12]


def key_id() -> str:
    return _key()[1]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path(storage_key: str) -> Path:
    base = Path(get_settings().evidence_dir).resolve()
    path = (base / storage_key).resolve()
    if base not in path.parents:                      # 저장소 밖 경로 차단
        raise ValueError("invalid storage key")
    return path


def put(storage_key: str, data: bytes) -> None:
    key, _ = _key()
    nonce = os.urandom(_NONCE)
    blob = nonce + AESGCM(key).encrypt(nonce, data, storage_key.encode())
    path = _path(storage_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with _lock:
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)


def get(storage_key: str) -> bytes:
    key, _ = _key()
    blob = _path(storage_key).read_bytes()
    return AESGCM(key).decrypt(blob[:_NONCE], blob[_NONCE:], storage_key.encode())


def delete(storage_key: str) -> None:
    """원본 삭제: 같은 크기의 무작위 값으로 덮어쓴 뒤 지운다 (최선 노력)."""
    path = _path(storage_key)
    if not path.exists():
        return
    size = path.stat().st_size
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    path.unlink()
