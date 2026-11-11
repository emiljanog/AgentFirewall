import unittest
from agentfirewall.policy import bash_decision, evaluate

class PolicyTests(unittest.TestCase):
    def test_safe_does_not_override_permissions(self):
        self.assertEqual(bash_decision('npm test').action, 'pass')
    def test_secrets(self):
        self.assertEqual(bash_decision('cat .env.production').action, 'deny')
    def test_destruction(self):
        self.assertEqual(bash_decision('rm -rf /srv/site').action, 'deny')
    def test_approval(self):
        self.assertEqual(bash_decision('curl https://example.com').action, 'ask')
    def test_compound(self):
        self.assertEqual(bash_decision('npm test; rm file').action, 'ask')
    def test_path_outside(self):
        p = {'cwd':'/tmp/project','tool_name':'Read','tool_input':{'file_path':'../secret.txt'}}
        self.assertEqual(evaluate(p).action, 'deny')
    def test_path_inside(self):
        p = {'cwd':'/tmp/project','tool_name':'Write','tool_input':{'file_path':'src/app.py'}}
        self.assertEqual(evaluate(p).action, 'pass')
    def test_path_sensitive(self):
        p = {'cwd':'/tmp/project','tool_name':'Read','tool_input':{'file_path':'.ssh/id_ed25519'}}
        self.assertEqual(evaluate(p).action, 'deny')
    def test_unknown_tool(self):
        p = {'cwd':'/tmp/project','tool_name':'mcp__other__fetch','tool_input':{}}
        self.assertEqual(evaluate(p).action, 'ask')
    def test_missing_input(self):
        self.assertEqual(evaluate({}).action, 'deny')

if __name__ == '__main__':
    unittest.main()
