"""Nested artifacts share the parent's resource and trust boundaries."""
import io
import unittest
import zipfile

from olc.archive import make_limits, read_archive
from olc.inspect import inspect_artifacts
from tests import helpers as H
from tests.test_archive import Recorder


def zipped(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return stream.getvalue()


class NestedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.files = H.Workdir()

    def tearDown(self):
        self.files.cleanup()

    def inspect(self, members, limits=None):
        artifact = self.files.tgz('source.tar.gz', members, cls='sdist')
        rule = H.rule('forbidden_asset', match=['(?i)Acme Type'])
        return inspect_artifacts([artifact], H.rules(rule), limits=limits)

    def test_content_identified_font_inside_renamed_zip_is_not_hidden(self):
        result = self.inspect({'package/renamed.bin': zipped({'x.bin': H.sfnt(H.FORBIDDEN)})})
        self.assertEqual(result['finding_verdict'], 'fail')
        reason = next(r for r in H.check(result)['reasons'] if r['code'] == 'name-record-match')
        self.assertEqual(reason['member'], 'package/renamed.bin!/x.bin')
        self.assertEqual(result['target']['artifacts'][0]['archive']['nested_archives_count'], 1)

    def test_nested_zip_and_kmz_without_identified_font_pass(self):
        result = self.inspect({'package/maps.kmz': zipped({'doc.kml': b'<kml/>'}),
                               'package/data.zip': zipped({'data.json': b'{}'})})
        self.assertEqual(result['finding_verdict'], 'pass', H.check(result))
        self.assertEqual(result['coverage']['unexamined'], [])

    def test_depth_budget_remains_incomplete(self):
        nested = zipped({'inside.zip': zipped({'again.zip': zipped({'data': b'x'})})})
        result = self.inspect({'package/data.zip': nested})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        self.assertIn('nested-depth-limit', {e['why'] for e in result['coverage']['unexamined']})

    def test_member_budget_is_shared_across_sibling_archives(self):
        result = self.inspect({'a.zip': zipped({'a': b'a', 'b': b'b'}),
                               'b.zip': zipped({'c': b'c', 'd': b'd'})}, {'max_members': 5})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        self.assertEqual(result['target']['artifacts'][0]['archive']['problem'], 'member-limit')

    def test_expansion_budget_includes_nested_bytes(self):
        result = self.inspect({'data.zip': zipped({'expanded': b'a' * 20000})},
                              {'max_total_bytes': 10000})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        self.assertEqual(result['target']['artifacts'][0]['archive']['problem'], 'total-limit')

    def test_nested_absolute_and_parent_paths_are_not_trusted(self):
        result = self.inspect({'package/data.zip': zipped({'/absolute': b'x', '../escape': b'y'})})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        reasons = {e['why'] for e in result['coverage']['unexamined']}
        self.assertIn('bad-path:absolute', reasons)
        self.assertIn('bad-path:parent-component', reasons)

    def test_corrupt_nested_archive_never_passes(self):
        result = self.inspect({'data.zip': b'PK\x03\x04not a valid zip'})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        self.assertIn('nested-archive-unreadable', {e['why'] for e in result['coverage']['unexamined']})

    def test_large_nested_buffer_is_explicitly_incomplete(self):
        result = self.inspect({'data.zip': zipped({'data': bytes(range(256)) * 10})},
                              {'content_cap': 100})
        self.assertEqual(result['finding_verdict'], 'incomplete')
        self.assertIn('nested-over-content-cap', {e['why'] for e in result['coverage']['unexamined']})

    def test_nested_reader_does_not_extract_files(self):
        artifact = self.files.zip('outer.zip', {'maps.kmz': zipped({'child': b'x'})})
        record = Recorder()
        summary = read_archive(artifact['path'], record, make_limits())
        self.assertIsNone(summary.problem)
        self.assertEqual(record.members, [('maps.kmz!/child', b'x')])
        self.assertEqual([p.name for p in self.files.path.iterdir()], ['outer.zip'])
