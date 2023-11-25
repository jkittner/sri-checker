from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import urllib.request
from collections.abc import Sequence

from bs4 import BeautifulSoup
from bs4.element import ResultSet
from bs4.element import Tag

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


def _check_integrity(filename: str, t: Tag) -> bool:
    path = t.get('src') or t.get('href')
    assert path is not None
    algo, hash_in_file = t['integrity'].split('-')
    hash_algo = HASHING_ALGOS.get(algo)
    if hash_algo is None:
        raise ValueError(f'unknown hashing algorithm: {algo!r}')

    # remote
    if path.startswith('http'):
        ret = urllib.request.urlopen(path, timeout=3)
        contents = ret.read()
    # local
    else:
        with open(path, 'rb') as f:
            contents = f.read()

    current_hash = base64.b64encode(hash_algo(contents).digest()).decode()
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
