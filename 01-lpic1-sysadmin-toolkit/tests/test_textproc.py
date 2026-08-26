from sysadmin_toolkit import textproc


def test_word_frequency(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("the quick fox the quick fox the")

    result = textproc.word_frequency(f, top_n=2)
    assert result[0] == ("the", 3)
    assert result[1] == ("quick", 2)


def test_word_frequency_case_insensitive(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Fox fox FOX")

    result = textproc.word_frequency(f)
    assert result == [("fox", 3)]


def test_dedupe_lines_keeps_first_and_order(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("b\na\nb\nc\na\n")

    result = textproc.dedupe_lines(f)
    assert result == ["b", "a", "c"]


def test_grep_lines_finds_match(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("one\ntwo error here\nthree\n")

    matches = textproc.grep_lines("error", f)
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_grep_lines_context(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("a\nb\nerror\nc\nd\n")

    matches = textproc.grep_lines("error", f, context=1)
    assert matches[0]["before"] == ["b"]
    assert matches[0]["after"] == ["c"]


def test_grep_lines_ignore_case(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Warning: disk full\n")

    assert textproc.grep_lines("warning", f) == []
    assert len(textproc.grep_lines("warning", f, ignore_case=True)) == 1


def test_extract_column(tmp_path):
    f = tmp_path / "sample.csv"
    f.write_text("name,age\nchris,30\nalex,25\n")

    names = textproc.extract_column(f, ",", 1, skip_header=True)
    assert names == ["chris", "alex"]


def test_extract_column_missing_field_skipped(tmp_path):
    f = tmp_path / "sample.csv"
    f.write_text("a,b,c\nx,y\n")

    values = textproc.extract_column(f, ",", 3)
    assert values == ["c"]
