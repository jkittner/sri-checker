import io
import re
import sys
import urllib.request
from unittest import mock

import pytest

from sri_checker import main

ERR_TXT = (
    r'[\/[a-zA-Z0-9-_]+(?:/test.html)?:{line_no} SRI-hash incorrect\n'
    r'expected: {expected_hash}\ngot: {current_hash}'
)


@pytest.fixture(autouse=True)
def mock_request():
    class Ret(io.BytesIO):
        def read(self):
            return b'foobar'

    with mock.patch.object(urllib.request, 'urlopen', return_value=Ret()):
        yield


def test_main_noop(tmpdir):
    test_input = (
        '<script src="https://example.com"></script>\n'
        '<link rel="stylesheet" href="https://example.com">\n'
    )
    test_file = tmpdir.join('test.html')
    test_file.write(test_input)

    assert main([str(test_file)]) == 0


def test_main_noop_stdin():
    test_input_bytes = (
        b'<script src="https://example.com"></script>\n'
        b'<link rel="stylesheet" href="https:/example.com">\n'
    )
    test_input = io.TextIOWrapper(io.BytesIO(test_input_bytes), 'UTF-8')
    with mock.patch.object(sys, 'stdin', test_input):
        assert main(['-']) == 0


def test_main_local_file(tmpdir):
    test_input_bytes = (
        b'<script src="foo.js" integrity="sha256-/vEGitHRn04CWTbom7anOKXL/oPtFwJsXhtpjB/3I9Q="></script>\n'  # noqa: 501
    )
    foo_js = tmpdir.join('foo.js')
    foo_js.write(b'let foo = "bar";\n')
    test_file = tmpdir.join('test.html')
    test_file.write(test_input_bytes)
    with tmpdir.as_cwd():
        assert main([str(test_file)]) == 0


def test_main_stdin_local_file(tmpdir):
    test_input_bytes = (
        b'<script src="foo.js" integrity="sha256-/vEGitHRn04CWTbom7anOKXL/oPtFwJsXhtpjB/3I9Q="></script>\n'  # noqa: 501
    )
    foo_js = tmpdir.join('foo.js')
    foo_js.write(b'let foo = "bar";\n')
    test_input = io.TextIOWrapper(io.BytesIO(test_input_bytes), 'UTF-8')

    with (
        mock.patch.object(sys, 'stdin', test_input),
        tmpdir.as_cwd(),
    ):
        assert main(['-']) == 0


def test_main_check_fails(tmpdir, capsys):
    test_input = b'''\
    <script src="https://example.com" integrity="sha384-cxOPjt7s7Iz0"></script>
    <link rel="stylesheet" href="https://example.com" integrity="sha384-sHL9N">
    '''
    test_file = tmpdir.join('test.html')
    test_file.write(test_input)
    main([str(test_file)]) == 1
    std, _ = capsys.readouterr()
    # script
    pattern = ERR_TXT.format(
        line_no=1,
        expected_hash='sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        current_hash='sha384-cxOPjt7s7Iz0',
    )
    m1 = re.findall(re.compile(pattern), std)
    assert len(m1) == 1
    # link
    pattern = ERR_TXT.format(
        line_no=2,
        expected_hash='sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        current_hash='sha384-sHL9N',
    )
    m2 = re.findall(re.compile(pattern), std)
    assert len(m2) == 1


def test_main_check_fails_stdin(capsys):
    test_input_bytes = b'''\
    <script src="https://example.com" integrity="sha384-cxOPjt7s7Iz0"></script>
    <link rel="stylesheet" href="https://example.com" integrity="sha384-sHL9N">
    '''
    test_input = io.TextIOWrapper(io.BytesIO(test_input_bytes), 'UTF-8')
    with mock.patch.object(sys, 'stdin', test_input):
        assert main(['-']) == 1

    std, _ = capsys.readouterr()
    # script
    pattern = ERR_TXT.format(
        line_no=1,
        expected_hash='sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        current_hash='sha384-cxOPjt7s7Iz0',
    )
    m1 = re.findall(re.compile(pattern), std)
    assert len(m1) == 1
    # link
    pattern = ERR_TXT.format(
        line_no=2,
        expected_hash='sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        current_hash='sha384-sHL9N',
    )
    m2 = re.findall(re.compile(pattern), std)
    assert len(m2) == 1


@pytest.mark.parametrize(
    'hash_str',
    (
        'sha256-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=',
        'sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        'sha512-ClAmHr0aOQ/tK/Mm8mc8FFWCpjQtUjIElz0CGTN/gWFqgGmwElh89WNfaSXxtWw2AjDBmyc1AO4BPgMGAb8kJQ==',  # noqa: E501
    ),
)
def test_main_hash_algos_noop(hash_str, tmpdir):
    test_input = f'''\
    <script src="https://example.com" integrity="{hash_str}"></script>
    <link rel="stylesheet" href="https://example.com" integrity="{hash_str}">
    '''
    test_file = tmpdir.join('test.html')
    test_file.write(test_input.encode())
    assert main([str(test_file)]) == 0


@pytest.mark.parametrize(
    'hash_str',
    (
        'sha256-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=',
        'sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G',  # noqa: E501
        'sha512-ClAmHr0aOQ/tK/Mm8mc8FFWCpjQtUjIElz0CGTN/gWFqgGmwElh89WNfaSXxtWw2AjDBmyc1AO4BPgMGAb8kJQ==',  # noqa: E501
    ),
)
def test_main_hash_algos_failure(hash_str, tmpdir, capsys):
    algo, _ = hash_str.split('-')
    test_input = f'''\
    <script src="https://example.com" integrity="{algo}-w6uP8Tcg6K"></script>
    <link rel="stylesheet" href="https://example.com" integrity="{algo}-ClAtK">
    '''
    test_file = tmpdir.join('test.html')
    test_file.write(test_input.encode())
    assert main([str(test_file)]) == 1

    std, _ = capsys.readouterr()
    # script
    pattern = ERR_TXT.format(
        line_no=1,
        expected_hash=hash_str,
        current_hash=f'{algo}-w6uP8Tcg6K',
    )
    m1 = re.findall(re.compile(pattern), std)
    assert len(m1) == 1
    # link
    pattern = ERR_TXT.format(
        line_no=2,
        expected_hash=hash_str,
        current_hash=f'{algo}-ClAtK',
    )
    m2 = re.findall(re.compile(pattern), std)
    assert len(m2) == 1


def test_main_hash_algo_not_found(tmpdir):
    test_input = '''\
    <script src="https://example.com" integrity="sha123-foobar"></script>
    '''
    test_file = tmpdir.join('test.html')
    test_file.write(test_input.encode())
    with pytest.raises(ValueError) as exc_info:
        main([str(test_file)])

    msg, = exc_info.value.args
    assert msg == "unknown hashing algorithm: 'sha123'"
