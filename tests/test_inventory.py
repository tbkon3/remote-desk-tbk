"""Inventario Windows su dati sintetici: nessuna lettura dal PC che esegue i test."""
import ctypes as ct
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import inventory as inv


def set_dword(pointer, value):
    ct.cast(pointer, inv.PDWORD)[0] = value


class InventoryTests(unittest.TestCase):
    def collect(self, section):
        with patch.object(inv.os, "name", "nt"):
            return inv.read_section(section)

    def test_unknown_section_and_platform(self):
        with patch.object(inv, "_dll", side_effect=AssertionError("accesso nativo")):
            for section in ("uninstall", "", None, {}):
                with self.subTest(section=section), self.assertRaises(ValueError):
                    inv.read_section(section)
            with patch.object(inv.os, "name", "posix"), self.assertRaises(RuntimeError):
                inv.read_section("services")

    def test_rows_and_text_are_bounded(self):
        result = inv._Result()
        with patch.object(inv, "MAX_ROWS", 1):
            self.assertTrue(result.add(name="B\x00" + "x" * 512))
            self.assertFalse(result.add(name="A"))
        doc = result.finish()
        self.assertTrue(doc["partial"])
        self.assertEqual(len(doc["rows"]), 1)
        self.assertEqual(len(doc["rows"][0]["name"]), inv.MAX_TEXT)
        self.assertNotIn("\x00", doc["rows"][0]["name"])

    def test_error_preserves_partial_results_without_raw_os_details(self):
        def fake(result):
            result.add(name="Studio")
            raise PermissionError(13, "dato-riservato")
        with patch.dict(inv.COLLECTORS, {"shares": fake}):
            doc = self.collect("shares")
        self.assertTrue(doc["partial"])
        self.assertEqual(doc["rows"], [{"name": "Studio"}])
        self.assertNotIn("dato-riservato", doc["note"])

    def test_local_share_paging_and_buffer_cleanup(self):
        pages = [
            (inv._Share * 2)(inv._Share("Zeta", 0, "Regia"), inv._Share("IPC$", 3, "")),
            (inv._Share * 1)(inv._Share("Archivio$", 0x80000000, None)),
        ]
        def enum(server, level, buf, limit, count, total, resume):
            self.assertIsNone(server)
            self.assertEqual(level, 1)
            index = ct.cast(resume, inv.PDWORD)[0]
            ct.cast(buf, inv.PHANDLE)[0] = ct.addressof(pages[index])
            set_dword(count, len(pages[index]))
            set_dword(resume, index + 1)
            return inv.MORE_DATA if index == 0 else 0
        lib = SimpleNamespace(NetShareEnum=enum, NetApiBufferFree=Mock())
        with patch.object(inv, "_dll", return_value=lib):
            doc = self.collect("shares")
        self.assertFalse(doc["partial"])
        self.assertEqual([(r["name"], r["type"]) for r in doc["rows"]],
                         [("Archivio$", "Disco (speciale)"), ("Zeta", "Disco")])
        self.assertEqual(lib.NetApiBufferFree.call_count, 2)

    def test_drive_lookup_only_uses_local_letters(self):
        def get(drive, buffer, size):
            self.assertRegex(drive, "^[A-Z]:$")
            if drive == "Z:":
                buffer.value = r"\\files.example\media"
                return 0
            if drive == "X:":
                return 1201
            return 2250
        lib = SimpleNamespace(WNetGetConnectionW=get)
        with patch.object(inv, "_dll", return_value=lib):
            doc = self.collect("drives")
        self.assertTrue(doc["partial"])
        self.assertEqual([r["drive"] for r in doc["rows"]], ["X:", "Z:"])
        self.assertEqual(doc["rows"][1]["remote"], r"\\files.example\media")

    def test_service_status_with_enumerate_only_rights(self):
        sample = (inv._Service * 1)()
        sample[0].name, sample[0].display = "StudioTest", "Studio Test"
        sample[0].status.state = 4
        def enum(manager, level, kind, states, buffer, size, needed, count, resume, group):
            self.assertEqual((manager, level, kind, states, group), (100, 0, 0x30, 3, None))
            ct.memmove(buffer, sample, ct.sizeof(sample))
            set_dword(count, 1)
            return 1
        lib = SimpleNamespace(OpenSCManagerW=Mock(return_value=100), CloseServiceHandle=Mock(),
                              EnumServicesStatusExW=enum)
        with patch.object(inv, "_dll", return_value=lib), patch.object(inv, "_service_start", return_value="Manuale"):
            doc = self.collect("services")
        lib.OpenSCManagerW.assert_called_once_with(None, None, 4)
        lib.CloseServiceHandle.assert_called_once_with(100)
        self.assertEqual(doc["rows"], [{"name": "StudioTest", "display": "Studio Test",
                                        "status": "In esecuzione", "start": "Manuale"}])

    def test_apps_deduplicate_views_but_keep_user_and_machine_scopes(self):
        registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_WOW64_32KEY=0x200,
                                   KEY_WOW64_64KEY=0x100, KEY_QUERY_VALUE=1, KEY_READ=9)
        registry.OpenKey = Mock(side_effect=lambda root, path, *args: nullcontext(path))
        registry.QueryInfoKey = Mock(return_value=(1, 2, 3))
        registry.EnumKey = Mock(return_value="Example")
        values = {"DisplayName": "Studio", "Publisher": "Example", "DisplayVersion": "1.0"}
        with patch.object(inv, "winreg", registry), patch.object(inv, "_dll", return_value=SimpleNamespace(RegGetValueW=Mock())), \
             patch.object(inv, "_user_hive", return_value=nullcontext(2)), \
             patch.object(inv, "_app_text", side_effect=lambda key, name, result, get: values[name]):
            doc = self.collect("apps")
        self.assertEqual([r["scope"] for r in doc["rows"]], ["Macchina", "Utente"])
        self.assertIn("MSIX", doc["note"])
        self.assertTrue(doc["partial"])
        views = {c.args[-1] for c in registry.OpenKey.call_args_list if c.args[0] in (1, 2)}
        self.assertEqual(views, {0x100 | 9, 0x200 | 9})

    def test_service_identity_cannot_supply_an_interactive_hive(self):
        with patch.object(inv, "_user_sid", return_value="S-1-5-18"), self.assertRaises(PermissionError):
            with inv._user_hive():
                self.fail("nessuna lettura del profilo di servizio")


if __name__ == "__main__":
    unittest.main()
