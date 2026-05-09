def test_cli_imports_shared_pipeline():
    import server_doctor.cli as cli

    assert hasattr(cli, "main")
    from server_doctor.pipeline import run_full_diagnosis, run_full_scan

    assert callable(run_full_scan)
    assert callable(run_full_diagnosis)
