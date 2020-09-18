import pytest
from ade import main

def test_argparse():
    # Test help 
    with pytest.raises(SystemExit) as wrapper:
        main(['-h'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_domain_arg():
    # Test regex for incorrect domain format
    with pytest.raises(SystemExit) as wrapper:
        main(['12345', '--no-creds', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 1

def test_user_arg():
    # Test regex for incorrect user format
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 1

def test_init_args(capfd):
    # Test init of EnumAD
    main(['domain.local', '-u', 'johndoe@domain.local', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None False False False False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_o(capfd):
    # Test init of EnumAD -o
    main(['domain.local', '-u', 'johndoe@domain.local', '-o', 'some/path', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False some/path False False False False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_s(capfd):
    # Test init of EnumAD -s
    main(['domain.local', '-u', 'johndoe@domain.local', '-s', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "True None False False False False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_smb(capfd):
    # Test init of EnumAD -smb
    main(['domain.local', '-u', 'johndoe@domain.local', '-smb', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None False False False True False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_kp(capfd):
    # Test init of EnumAD -kp
    main(['domain.local', '-u', 'johndoe@domain.local', '-kp', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None False True False False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_bh(capfd):
    # Test init of EnumAD -bh
    main(['domain.local', '-u', 'johndoe@domain.local', '-bh', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None True False False False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_spn(capfd):
    # Test init of EnumAD -spn
    main(['domain.local', '-u', 'johndoe@domain.local', '-spn', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None False False True False False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_sysvol(capfd):
    # Test init of EnumAD -sysvol
    main(['domain.local', '-u', 'johndoe@domain.local', '-sysvol', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None False False False False True" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out


def test_init_args_all(capfd):
    # Test init of EnumAD -all
    main(['domain.local', '-u', 'johndoe@domain.local', '--all', '--dry-run'])
    out, err = capfd.readouterr()
    assert "domain.local" in out
    assert "johndoe@domain.local" in out
    assert "False None True True True True False" in out
    assert "['domain', 'local'] dc=domain,dc=local," in out