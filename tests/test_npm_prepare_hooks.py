import json
from clonepeek.detectors import inspect
def test_prepare_lifecycle_siblings():
    scripts={'preprepare':'echo before','postprepare':'echo after','test':'echo test'}
    findings=inspect('package.json',json.dumps({'scripts':scripts}))
    assert {f.title for f in findings}=={'npm lifecycle script: preprepare','npm lifecycle script: postprepare'}
