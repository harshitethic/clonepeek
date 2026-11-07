import json
from clonepeek.detectors import inspect
def test_after_publish_hooks():
    findings=inspect('package.json',json.dumps({'scripts':{'publish':'echo published','postpublish':'echo done','start':'echo start'}}))
    assert {f.title for f in findings}=={'npm lifecycle script: publish','npm lifecycle script: postpublish'}
