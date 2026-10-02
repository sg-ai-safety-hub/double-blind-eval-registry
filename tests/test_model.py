from registry.model import Check, Status, check


def test_a_check_reports_the_status_and_detail_it_returns():
    @check("digests")
    def passing():
        return Status.PASS, "recomputes"

    assert passing() == Check("digests", Status.PASS, "recomputes")


def test_any_exception_inside_a_check_is_a_fail():
    # Fail closed.
    @check("consent")
    def broken():
        raise KeyError("boom")

    result = broken()
    assert (result.id, result.status) == ("consent", Status.FAIL)
    assert result.detail == "error while checking: KeyError: 'boom'"
