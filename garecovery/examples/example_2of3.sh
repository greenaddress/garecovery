TEST_DATA_DIR=garecovery/tests/test_data/
garecovery-cli --mnemonic-file=$TEST_DATA_DIR/mnemonic_1.txt --testnet 2of3 --rescan --backup-mnemonic-file=$TEST_DATA_DIR/mnemonic_2.txt
