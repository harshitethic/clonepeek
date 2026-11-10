from clonepeek.detectors import inspect
def test_dependencies_hook():
    findings=inspect('package.json','{"scripts":{"dependencies":"echo changed","test":"echo test"}}')
    assert len(findings)==1
    assert findings[0].title=='npm lifecycle script: dependencies'
