def test_same_plugin_registered_twice_is_idempotent_but_a_different_check_still_clashes():
    from homelabnext.invariants.api import Check, Registry

    def same(ctx):  # noqa: ARG001
        return None

    def other(ctx):  # noqa: ARG001
        return None

    reg = Registry()
    first = reg.register(Check("X-99", "statement", same))
    assert reg.register(Check("X-99", "statement", same)) is first
    with __import__("pytest").raises(ValueError):
        reg.register(Check("X-99", "statement", other))
