TEST_DATA_DIR=garecovery/tests/test_data/
garecovery-cli --mnemonic-file $TEST_DATA_DIR/mnemonic_1.txt 2of3 --recovery-mnemonic $TEST_DATA_DIR/mnemonic_2.txt --search-subaccounts=1 --destination-address=mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs --key-search-depth=10 --scan-from=1535760000 --rpc-timeout-minutes=3
