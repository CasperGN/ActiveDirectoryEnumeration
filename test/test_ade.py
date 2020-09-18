import ade
import pytest
import ldap3
import contextlib
import sys
import io

def test_enumAD_runWithoutCreds():
    # Negative testing to show we can
    # Here we validate that we can import, initialize EnumAD and execute runWithoutCreds (and fail)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        with pytest.raises(SystemExit) as ldaperr:
            adeEnum = ade.EnumAD('domain.local', True, False, False, False, False, False, False, True)
            adeEnum.runWithoutCreds()
        assert "ERROR" in out.getvalue()
        assert "Failed to bind to LDAPS server: " in out.getvalue()