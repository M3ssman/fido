import io
from types import SimpleNamespace

from fido import toxml


def test_toxml_main_renders_single_row(monkeypatch, capsys):
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="999"))
    monkeypatch.setattr(
        toxml.sys,
        "stdin",
        io.StringIO('OK,0,fmt/1000,"Sample Format","Sample Sig",9,sample.bin,application/test,byte\n'),
    )

    toxml.main()

    output = capsys.readouterr().out
    assert "<fido_output>" in output
    assert "<signature_version>999</signature_version>" in output
    assert "<filename>sample.bin</filename>" in output
    assert "<puid>fmt/1000</puid>" in output
    assert "<filesize>9</filesize>" in output
    assert output.strip().endswith("</fido_output>")


def test_toxml_main_renders_multiple_rows(monkeypatch, capsys):
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))
    monkeypatch.setattr(
        toxml.sys,
        "stdin",
        io.StringIO(
            "OK,1,fmt/1,Format A,Sig A,4,a.bin,text/plain,byte\n"
            "KO,2,,Unknown,,8,b.bin,,extension\n"
        ),
    )

    toxml.main()

    output = capsys.readouterr().out
    assert output.count("<file>") == 2
    assert "<filename>a.bin</filename>" in output
    assert "<filename>b.bin</filename>" in output
    assert "<status>KO</status>" in output
