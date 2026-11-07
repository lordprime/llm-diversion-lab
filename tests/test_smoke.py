def test_package_imports() -> None:
    import agents
    import cell
    import control

    assert control.__version__ == "0.0.0"
    assert cell is not None
    assert agents is not None
