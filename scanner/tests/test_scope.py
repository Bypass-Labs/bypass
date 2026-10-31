"""Analysis scope is independent of build inputs and explicit safety exclusions."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from bypass_scanner.discovery.sarif import normalize
from bypass_scanner.repository.scope import select, excluded_category, ignore_patterns
from bypass_scanner.repository.snapshot import snapshot


class ScopeTests(unittest.TestCase):
    def test_naming_boundaries_and_independent_opt_ins(self):
        tests=['test/a.js','tests/fixtures/a.py','src/__tests__/a.ts','lib/FooTest.java','App.Tests/Main.cs','src/foo_test.go','src/check.spec.ts','src/test_foo.py']
        examples=['examples/a.ts','demo/a.py','benchmarks/test.go','benches/main.rs']
        generated=['plugin/runtime/src/a.mjs','src/__generated__/a.cs','vendor/a.go','dist/a.js','src/a.generated.ts']
        for category,names,option in [('tests',tests,'includeTests'),('examples',examples,'includeExamples'),('generated',generated,'includeGenerated')]:
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(excluded_category(name,{}),category)
                    self.assertIsNone(excluded_category(name,{option:True}))
        for name in ['src/contest.py','src/specification.ts','src/latest.go','src/testimony.js','.github/workflows/test.yml','scripts/build.mjs']:
            self.assertIsNone(excluded_category(name,{}),name)
        self.assertEqual(excluded_category('examples/tests/a.py',{'includeTests':True}),'examples')
        self.assertEqual(ignore_patterns({'includeTests':True,'includeExamples':True,'includeGenerated':True}),[])

    def test_context_and_custom_ignores_in_git_and_plain_directories(self):
        for git in [False,True]:
            with self.subTest(git=git), tempfile.TemporaryDirectory() as name:
                root=Path(name)
                for path in ['src/main.py','tests/keep.py','examples/keep.py','plugin/runtime/keep.py','dist/tracked.py','tests/secret.py','.env','token.key','node_modules/ignored.py']:
                    file=root/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('pass\n')
                root.joinpath('.bypassignore').write_text('tests/secret.py\n')
                if git:
                    subprocess.run(['git','init','-q',str(root)],check=True)
                self.assertNotIn('dist/tracked.py',snapshot(root)['files'])
                recorded=snapshot(root,include_generated=True)
                analysis,manifest=select(recorded,{})
                self.assertIn('tests/keep.py',recorded['files'])
                self.assertNotIn('tests/keep.py',analysis['files'])
                for path in ['.env','token.key','node_modules/ignored.py','tests/secret.py']:
                    self.assertNotIn(path,recorded['files'])
                included,_=select(recorded,{'includeTests':True,'includeExamples':True,'includeGenerated':True})
                self.assertEqual(included['files'],recorded['files'])
                self.assertEqual(manifest['summary']['excludedFiles'],4)
                document={'version':'2.1.0','runs':[{'results':[{'ruleId':'r','message':{'text':'explicitly ignored'},
                    'locations':[{'physicalLocation':{'artifactLocation':{'uri':'tests/secret.py'},'region':{'startLine':1}}}]}]}]}
                filtered=[]
                values,_=normalize(document,'import',included,root,'import.sarif',filtered=filtered)
                self.assertEqual(values,[]);self.assertEqual(filtered[0]['categories'],['source_policy'])

    def test_primary_locations_determine_scope_not_related_locations(self):
        files={name:{'sha256':'hash','lineCount':1} for name in ['src/a.py','tests/a.py']}
        scoped,_=select({'revision':'revision','files':files},{})
        def location(path):return {'physicalLocation':{'artifactLocation':{'uri':path},'region':{'startLine':1}}}
        test=location('tests/a.py');prod=location('src/a.py')
        results=[{'ruleId':'r','message':{'text':'test sink'},'locations':[test],'relatedLocations':[prod]},
                 {'ruleId':'r','message':{'text':'production sink'},'locations':[prod],'relatedLocations':[test]},
                 {'ruleId':'r','message':{'text':'mixed locations'},'locations':[test,prod]},
                 {'ruleId':'r','message':{'text':'no primary location'}}]
        document={'version':'2.1.0','runs':[{'tool':{'driver':{}},'results':results}]}
        filtered=[]
        values,warnings=normalize(document,'import',scoped,Path('/source'),'import.sarif',filtered=filtered)
        self.assertEqual(len(values),3);self.assertEqual(warnings,[])
        self.assertEqual(filtered[0]['origin']['resultIndex'],0)
        self.assertEqual(filtered[0]['categories'],['tests'])
        self.assertTrue(all(loc['path']=='src/a.py' for value in values for loc in value['locations']))
        self.assertEqual(len(document['runs'][0]['results']),4)
