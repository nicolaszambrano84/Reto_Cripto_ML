from key_exchange.bonus import run_bonus_dukpt


def test_run_bonus_dukpt_decodes_known_ciphertext(capsys):
    bdk = bytes.fromhex('39EDE3A9437F3FF561898D1F6FABBD25')

    run_bonus_dukpt(bdk)

    captured = capsys.readouterr()
    assert 'BONUS DUKPT' in captured.out
    assert 'Mensaje en claro descifrado' in captured.out
    assert 'MELI_Rocks' in captured.out
