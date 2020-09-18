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

def test_init_args():
    # Test init of EnumAD
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_o():
    # Test init of EnumAD -o
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-o', 'some/path', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_s():
    # Test init of EnumAD -s
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-s', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_smb():
    # Test init of EnumAD -smb
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-smb', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_kp():
    # Test init of EnumAD -kp
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-kp', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_bh():
    # Test init of EnumAD -bh
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-bh', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_spn():
    # Test init of EnumAD -spn
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-spn', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_sysvol():
    # Test init of EnumAD -sysvol
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '-sysvol', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0

def test_init_args_all():
    # Test init of EnumAD -all
    with pytest.raises(SystemExit) as wrapper:
        main(['domain.local', '-u', 'johndoe@domain.local', '--all', '--dry-run'])
    assert wrapper.type == SystemExit
    assert wrapper.value.code == 0