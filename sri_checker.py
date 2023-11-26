from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import sys
import urllib.request
from collections.abc import Sequence
from typing import Callable
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup
from bs4.element import ResultSet
from bs4.element import Tag

if TYPE_CHECKING:
    from hashlib import _Hash

HASHING_ALGOS = {
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}


def _find_tags(src: str) -> list[ResultSet[Tag]]:
    soup = BeautifulSoup(src, 'html.parser')
    links: ResultSet[Tag] = soup.find_all(
        name='link',
        attrs={'rel': 'stylesheet'},
    )
    links = [
        i for i in links if i.has_attr('href') and i.has_attr('integrity')
    ]
    scripts: ResultSet[Tag] = soup.find_all(name='script')
    scripts = [
        i for i in scripts if i.has_attr('src') and i.has_attr('integrity')
    ]
    links.extend(scripts)
    links.sort(key=lambda x: x.sourceline)
    return links


@functools.cache
def _open_resource(path: str, hash_algo: Callable[[str], _Hash]) -> str:
    """this function is split out so that we can cache the result"""
    # remote
    if path.startswith('http'):
        ret = urllib.request.urlopen(path, timeout=3)
        contents = ret.read()
    # local
    else:
        with open(path, 'rb') as f:
            contents = f.read()
    return base64.b64encode(hash_algo(contents).digest()).decode()


def _check_integrity(filename: str, t: Tag) -> bool:
    path = t.get('src') or t.get('href')
    assert path is not None
    algo, hash_in_file = t['integrity'].split('-')
    hash_algo = HASHING_ALGOS.get(algo)
    if hash_algo is None:
        raise ValueError(f'unknown hashing algorithm: {algo!r}')

    current_hash = _open_resource(path=path, hash_algo=hash_algo)
    if current_hash != hash_in_file:
        print(
            f'{filename}:{t.sourceline} SRI-hash incorrect\n'
            f'expected: {algo}-{current_hash}\n'
            f'got: {algo}-{hash_in_file}\n',
        )
        return True
    else:
        return False


def _check_file(filename: str) -> int:
    if filename == '-':
        contents = sys.stdin.buffer.read().decode()
    else:
        with open(filename) as f:
            contents = f.read()

    tags = _find_tags(contents)
    ret = 0
    for t in tags:
        ret |= _check_integrity(filename, t)
    return ret


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args(argv)
    ret = 0
    for filename in args.filenames:
        ret |= _check_file(filename)
    return ret


if __name__ == '__main__':
    raise SystemExit(main())
