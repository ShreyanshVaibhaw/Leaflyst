from abx_api.export_safety import csv_cell


def test_csv_cell_neutralizes_formula_prefixes_after_whitespace() -> None:
    for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=WEBSERVICE(A1)"):
        assert csv_cell(value) == "'" + value


def test_csv_cell_preserves_inert_values_and_non_strings() -> None:
    assert csv_cell("safe") == "safe"
    assert csv_cell("'already inert") == "'already inert"
    assert csv_cell(42) == 42
