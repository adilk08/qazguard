import os,tempfile,unittest
from pathlib import Path
TEMP=tempfile.TemporaryDirectory()
os.environ.update(QAZGUARD_TESTING='1',PUBLIC_ORIGIN='http://localhost',QAZGUARD_TEST_DB=str(Path(TEMP.name)/'cloud.db'),SETUP_CODE='isolated-test-code')
os.environ.pop('DATABASE_URL',None)
import cloud

class CloudTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=cloud.app.test_client()
        cls.headers={'Origin':'http://localhost'}
        # A public visitor cannot claim the first administrator.
        r=cls.client.post('/api/auth',json={'username':'owner','password':'testing-password-123'},headers=cls.headers)
        assert r.status_code==403
        r=cls.client.post('/api/auth',json={'username':'owner','password':'testing-password-123','setup_code':'isolated-test-code'},headers=cls.headers)
        assert r.status_code==200
    def test_login_required(self):
        r=cloud.app.test_client().get('/api/business')
        self.assertEqual(r.status_code,401)
    def test_wrong_origin_rejected(self):
        r=self.client.post('/api/report',json={'mode':'summary'},headers={'Origin':'https://evil.example'})
        self.assertEqual(r.status_code,403)
    def test_report_totals(self):
        r=self.client.post('/api/report',json={'mode':'debt'},headers=self.headers)
        self.assertEqual(r.status_code,200)
        data=r.get_json()
        self.assertEqual(data['debt'],sum(row[5] for row in data['rows']))
        self.assertEqual(data['count'],sum(x['value'] for x in data['histogram']))
    def test_edit_preserves_client_count(self):
        before=self.client.get('/api/business').get_json()
        row=before['clients'][0]
        r=self.client.post('/api/create',json=dict(row,kind='client',company='Edited synthetic company'),headers=self.headers)
        self.assertEqual(r.status_code,200)
        after=self.client.get('/api/business').get_json()
        self.assertEqual(len(before['clients']),len(after['clients']))
        self.assertEqual(after['clients'][0]['company'],'Edited synthetic company')
    def test_backup_excludes_credentials(self):
        r=self.client.get('/api/backup')
        self.assertEqual(r.status_code,200)
        data=r.get_json()
        self.assertEqual(set(data),{'clients','orders','payments'})
        self.assertNotIn('password',r.get_data(as_text=True))
    def test_static_allowlist(self):
        self.assertEqual(self.client.get('/business.js').status_code,200)
        self.assertEqual(self.client.get('/.env.local').status_code,404)
        self.assertEqual(self.client.get('/cloud.py').status_code,404)
    def test_analyst_cannot_read_rows(self):
        r=self.client.post('/api/user',json={'username':'analyst-test','password':'testing-password-123','role':'analyst'},headers=self.headers)
        self.assertEqual(r.status_code,200)
        analyst=cloud.app.test_client()
        analyst.post('/api/auth',json={'username':'analyst-test','password':'testing-password-123'},headers=self.headers)
        data=analyst.get('/api/business').get_json()
        self.assertEqual(data['clients'],[])
        r=analyst.post('/api/report',json={'mode':'summary'},headers=self.headers)
        self.assertEqual(r.get_json()['rows'],[])
        r=analyst.post('/api/create',json={'kind':'client','name':'Not allowed'},headers=self.headers)
        self.assertEqual(r.status_code,403)
    def test_security_headers(self):
        r=self.client.get('/')
        self.assertEqual(r.headers['X-Content-Type-Options'],'nosniff')
        self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])

if __name__=='__main__':unittest.main()
