import pytest
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.matano import MatanoPythonBackend

@pytest.fixture
def matano_backend():
    return MatanoPythonBackend()

def test_matano_and_expression(matano_backend : MatanoPythonBackend, snapshot):
    ret = matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    )

    assert ret[0] == snapshot

def test_matano_or_expression(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    )[0] == snapshot

def test_matano_and_or_expression(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    )[0] == snapshot

def test_matano_or_and_expression(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    )[0] == snapshot

def test_matano_in_expression(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    )[0] == snapshot

def test_matano_regex_query(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    )[0] == snapshot

def test_matano_cidr_query(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    )[0] == snapshot

def test_matano_field_name_with_whitespace(matano_backend : MatanoPythonBackend, snapshot):
    assert matano_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                    fieldA|cidr: 
                        - 192.168.0.0/14
                        - 192.168.0.0/14
                condition: sel
        """)
    )[0] == snapshot

def test_cidr(matano_backend: MatanoPythonBackend, snapshot):
    r1 = SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldB|cidr: 192.168.0.0/14
        fieldA|cidr: 
            - 192.168.0.0/14
            - 192.168.0.0/14
    condition: sel
""")
    ret = matano_backend.convert(r1)
    assert ret[0] == snapshot

def test_wildcards(matano_backend: MatanoPythonBackend, snapshot):
    r1 = SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    selection:
        CommandLine:
            - '*netsh* wlan show profile*'
            - '*netsh wlan show profile*'
    condition: selection
""")
    ret = matano_backend.convert(r1)
    assert ret[0] == snapshot


def test_keywords(matano_backend: MatanoPythonBackend):
    rule = SigmaCollection.from_yaml("""
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
description: Detects setting proxy
author: Ömer Günal
references:
  - https://attack.mitre.org/techniques/T1090/
date: 2020/06/17
modified: 2021/11/27
logsource:
  product: linux
detection:
  keywords:
    - 'http_proxy=*'
    - 'https_proxy=*'
  condition: keywords
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.defense_evasion
""")
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        matano_backend.convert(rule)

    rule2 = SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    execve:
        type: 'EXECVE'
    truncate:
        - 'truncate'
        - '-s'
    dd:
        - 'dd'
        - 'if='
    filter:
        - 'of='
    condition: execve and (all of truncate or (all of dd and not filter))
""")
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        matano_backend.convert(rule2)

def test_output_detection(matano_backend: MatanoPythonBackend):
    r1 = SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    selection:
        CommandLine:
            - '*netsh* wlan show profile*'
            - '*netsh wlan show profile*'
    condition: selection
""")
    ret = matano_backend.convert(r1, "detection")
    print(ret)
