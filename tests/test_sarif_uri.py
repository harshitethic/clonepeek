from clonepeek.detectors import inspect
from clonepeek.formats import sarif
def test_sarif_paths_are_uris():
    findings=inspect('space #/%/package.json','{"scripts":{"install":"echo hi"}}')
    uri=sarif(findings)['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert uri=='space%20%23/%25/package.json'
