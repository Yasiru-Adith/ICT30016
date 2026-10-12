import tempfile
import unittest
import time
from pathlib import Path
from edr.core import event, Store
from edr.rules.broken_auth import BrokenAuth
from edr.rules.registry import load_rules
from edr.response import respond
from edr.collectors.http_auth import AuthenticationCollector
from dashboard import status

class Tests(unittest.TestCase):
    def values(self, offsets, source='192.0.2.20'):
        base = time.time()-20
        return [event('test','authentication_failure',{'service':'juice_shop','source_ip':source,'target_ip':'192.0.2.10','target_port':3000},base+n) for n in offsets]
    def test_threshold_persistence_dashboard(self):
        rule=BrokenAuth({})
        values=self.values([0,2,4,6,8,9])
        for v in values[:4]: self.assertEqual(rule.process(v),[])
        alert=rule.process(values[4])[0]
        self.assertEqual(rule.process(values[5]),[])
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'db.sqlite')
            db=Store(path)
            for v in values[:5]: db.add('events',v)
            respond(alert,db)
            data=status(path)
            self.assertEqual(data['counts'],{'events':5,'alerts':1,'responses':1})
            self.assertEqual(data['alerts'][0]['severity'],3)
            self.assertEqual(len(data['alerts'][0]['evidence_event_ids']),5)
            db.close()
    def test_window_and_isolation(self):
        rule=BrokenAuth({})
        for v in self.values([0,3,6,9,12]): self.assertEqual(rule.process(v),[])
        rule=BrokenAuth({})
        for i,v in enumerate(self.values([0,1,2,3,4])):
            v['data']['source_ip']=str(i)
            self.assertEqual(rule.process(v),[])
    def test_late_event_and_rearm(self):
        rule=BrokenAuth({})
        values=self.values([0,1,2,3,4,20,21,22,23,24])
        alerts=[a for v in values for a in rule.process(v)]
        self.assertEqual(len(alerts),2)
        self.assertEqual(rule.process(values[0]),[])
    def test_collector(self):
        c=AuthenticationCollector('lab','192.0.2.10',3000)
        request='100\t1\t192.0.2.20\t192.0.2.10\t50000\t3000\tPOST\t/rest/user/login\t\t1\n'
        response='101\t1\t192.0.2.10\t192.0.2.20\t3000\t50000\t\t\t401\t2\n'
        self.assertIsNone(c.parse(request))
        self.assertEqual(c.parse(response)['data']['service'],'juice_shop')
        self.assertIsNone(c.parse(response))
        c.parse(request.replace('/rest/user/login','/other'))
        self.assertIsNone(c.parse(response))
    def test_rule_registration(self):
        self.assertEqual(len(load_rules({'BA-001':{'enabled':True}})),1)
        with self.assertRaises(ValueError):load_rules({'unknown':{'enabled':True}})

if __name__=='__main__': unittest.main()
