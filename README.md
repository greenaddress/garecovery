Recover coins from GreenAddress wallets

Build status: [![Build Status](https://travis-ci.org/greenaddress/garecovery.png?branch=master)](https://travis-ci.org/greenaddress/garecovery)

For more information on the GreenAddress service, subaccount types and
recovery, please read the [GreenAddress FAQ](https://greenaddress.it/en/faq)

# Dependencies for Ubuntu & Debian
```
$ sudo apt-get update -qq
$ sudo apt-get install python3-pip python3-dev build-essential python3-virtualenv -yqq
```

# Install
```
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip install --require-hashes -r tools/requirements.txt
$ pip install .
```

# Summary
The GreenAddress Recovery Tool allows you to recover coins from your
GreenAddress account(s) if you cannot use the normal mechanisms for making
payments. This could be due to one of the following scenarios:

* You lose access to your two factor authentication (2FA) mechanism
* The GreenAddress service becomes unavailable

There are two recovery scenarios depending on whether the coins are in a
GreenAddress 2of2 or a 2of3 subaccount. If you have an nlocktimes.zip
recovery file that was emailed to you by the service, then the 2of2 proceedure
should be followed.

The recovery tool supports recovering from both types of subaccounts.

## 2of2 Recovery
Coins held in a 2of2 account need to be signed by both you and GreenAddress.
Provided you have nLocktime emails enabled in your settings, the service
automatically generates special "nLockTime" transactions, pre-signed by
GreenAddress but not spendable until some time in the future (the nLockTime).

To recover coins from a 2of2 account you simply wait until each nLockTime
transaction becomes spendable (90 days by default), then countersign using
the recovery tool and broadcast. The coins are sent to a key derived
from your login mnemonics which you can then sweep into any wallet.

You will need:

1) The latest nlocktimes.zip file sent to your email address from GreenAddress  
2) Your GreenAddress mnemonic  
3) The recovery tool

To run the recovery tool in 2of2 mode:
```
$ garecovery-cli 2of2 --nlocktime-file /path/to/downloaded/nlocktimes.zip -o garecovery.csv
```

Enter your mnemonic when prompted. The recovery tool will print a summary of the
recovery transactions and also write them to a file `garecovery.csv`.

_WARNING_
`garecovery.csv` contains the private keys to which the coins will
be sent. Be sure to perform the recovery on a device you trust and take care
to delete the recovery csv file securely when you are finished with it.

A sample of the printed summary output is:
```
mnemonic: <your mnemonic here...>
    tx id lock time      total out                destination address     coin value
--------- --------- -------------- ---------------------------------- --------------
7a00ab...   1139186 830673.85 bits 19G11T26M6xYwbq5UpJPtGrXbsdQyzpCsx 830673.85 bits

total value = 830673.85 bits in 1 utxo
```

Here you can see the file contains a transaction worth 830673.85 bits, with
locktime = 1139186. The locktime indicates the block number that the bitcoin
blockchain must reach before the coins are available for recovery. You can
find the current block number (also known as the block height) using your local
full node or many available online tools, for example https://blockexplorer.com

Once the transactions are spendable they can be broadcast onto the network. The
raw transactions are in the csv file, along with the private key for the
address they send their coins to. You can broadcast these raw transactions
using your full node via RPC or online tools such as:

https://blockexplorer.com/tx/send  
https://www.smartbit.com.au/txs/pushtx

## 2of3 Recovery
*Note for 0.17 users:* it is now possible to specify `--ignore-mempool`,
which makes the procedure much faster (by using `scantxoutset`).
However, as the flag suggests, it does not consider the transactions
that are still in the mempool.

In the case of 2of3 subaccounts you hold the mnemonics for 2 keys: the
default key used for day to day spending and a backup key used for recovery.
Coins held in a 2of3 account can be spent either by signing with your
default key and the GreenAddress key under normal circumstances, or by
signing with both your default and backup keys for recovery.

Unlike 2of2 where GreenAddress sends nLocktime transactions to you for
recovery, unspent coins in 2of3 subaccounts are only discoverable by
scanning the blockchain to look for them. The recovery tool connects
to your bitcoin core full node in order to perform this scanning for
you when recovering.

You will need:

1) A bitcoin core full node configured for local RPC access  
2) The recovery tool  
3) Your GreenAddress mnemonic  
4) The GreenAddress mnemonic for your 2of3 account  
5) The GreenAddress extended public key (xpub) for your 2of3 account  
6) A destination bitcoin address to send the recovered coins to

Setting up and running a bitcoin node is beyond the scope of this document
but instructions are readily available online. Ensure your node is
running, fully synced and you are able to connect to the RPC interface. You can
verify this using a command like:
```
/path/to/bitcoin-core/bin/bitcoin-cli getblockchaininfo
```

Also note that wallet functionality must not be disabled on your node.

Run the recovery tool in 2of3 mode:
```
$ garecovery-cli 2of3 --destination-address=XXXX -o garecovery.csv --ga-xpub=YYYY
```

The tool will prompt you for your mnemonic, recovery mnemonic and xpub. You
should have noted these details down when you created the 2of3 subaccount.

The tool will then connect to your node to scan for the 2of3 transactions.
This may take quite a long time. You can check the scan progress either by
looking in the bitcoind log file or in the bitcoin GUI.

If any recoverable coins were found the tool will display a summary of
them on the console and write the details to the output csv file ready for
broadcasting using the same steps as detailed above for 2of2 subaccounts.

# Troubleshooting

If you find any bugs, or have suggestions or patches, please raise them on
the [garecovery github project](https://github.com/greenaddress/garecovery).
