import pytest
import os
import shutil
from cvebased.repo import (
    compile_cve,
    parse_md,
    add_cve_front_matter,
)


def test_compile_cve():
    compile_cve('./tmp', {'id': 'CVE-2020-14882', 'pocs': ['http://example.com/poc'], 'advisory': 'lorem ipsum'})

    want_filepath = './tmp/cve/2020/14xxx/CVE-2020-14882.md'
    assert os.path.exists(want_filepath)

    with open(want_filepath, 'r') as f:
        fm, md = parse_md(f.read())
        assert fm['id'] == 'CVE-2020-14882'
        assert fm['pocs'] == ['http://example.com/poc']
        assert md == 'lorem ipsum'

    # cleanup
    shutil.rmtree('./tmp/cve', ignore_errors=True)


def test_add_cve_front_matter():
    # scenario: cve already exists
    compile_cve('./tmp', {'id': 'CVE-2020-14882', 'pocs': ['http://example.com/poc'], 'advisory': 'lorem ipsum'})
    add_cve_front_matter('./tmp', {'id': 'CVE-2020-14882', 'courses': ['http://vulhub.org']})

    want_filepath = './tmp/cve/2020/14xxx/CVE-2020-14882.md'
    with open(want_filepath, 'r') as f:
        fm, md = parse_md(f.read())
        assert fm['id'] == 'CVE-2020-14882'
        assert fm['courses'] == ['http://vulhub.org']
        assert md == 'lorem ipsum'

    # scenario: cve does not yet exist
    add_cve_front_matter('./tmp', {'id': 'CVE-2020-14883', 'courses': ['http://pentesterlab.com']})
    want_filepath = './tmp/cve/2020/14xxx/CVE-2020-14883.md'
    with open(want_filepath, 'r') as f:
        fm, md = parse_md(f.read())
        assert fm['id'] == 'CVE-2020-14883'
        assert fm['courses'] == ['http://pentesterlab.com']

    # cleanup
    shutil.rmtree('./tmp/cve', ignore_errors=True)
