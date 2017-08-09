Recover funds from GreenAddress wallets

Please also see the GreenAddress FAQ: https://greenaddress.it/en/faq.html

# Install
```
$ virtualenv venv
$ source venv/bin/activate
$ pip install --require-hashes -r tools/requirements.txt
$ pip install .
```

# Summary
The GreenAddress Recovery Tool allows you to recover funds from your
GreenAddress account(s) if you cannot use the normal mechanisms for making
payments. This could be due to one of the following scenarios:

* You lose access to your two factor authentication (2FA) mechanism
* The GreenAddress service becomes unavailable

There are two recovery scenarios depending on the GreenAddress subaccount type
which the funds are deposited in: 2of2 and 2of3. The recovery tool supports
both scenarios.

## 2of2 Recovery
Funds held in a 2of2 account need to be signed by both the user and
GreenAddress. Whenever funds are deposited into the account the GreenAddress
service automatically generates a special transaction, called an nLockTime
transaction, pre-signed by GreenAddress but not spendable until some time in
the future (the nLockTime).
To recover funds from a 2of2 account you can simply wait until the nLockTime
transaction becomes spendable (default 90 days), countersign it and then
broadcast the transaction thus recovering the funds. The destination address
for the recovery transaction is controlled by a single key which the recovery
too can derive from you mnemonic.

You will need:

1) The latest nlocktimes.zip file sent to your email address from GreenAddress  
2) Your GreenAddress mnemonic  
3) The recovery tool

To run the recovery tool in 2of2 mode:
```
$ garecovery-cli 2of2 --nlocktime-file /path/to/downloaded/nlocktimes.zip -o garecovery.csv
```

When prompted enter your mnemonic. The recovery tool will show a summary of the
recovery transactions and also write them to garecovery.csv.
* WARNING * garecovery.csv contains private keys

```
mnemonic: <your mnemonic here...>
    tx id lock time      total out                destination address     coin value
--------- --------- -------------- ---------------------------------- --------------
7a00ab...   1139186 830673.85 bits 19G11T26M6xYwbq5UpJPtGrXbsdQyzpCsx 830673.85 bits

total value = 830673.85 bits in 1 utxo
```

Here we can see that the file contains a transaction worth 830673.85 bits, with
locktime = 1139186. The locktime indicates the block number required before the
funds are available for recovery. You can find the current blockheight using
man available online tools, for example https://blockexplorer.com/

Once the transactions are spendable they can be broadcast onto the network. The
raw transactions are in the csv file, along with the private key for the
destination address. There are various sites where you can broadcast raw
transactions including:

https://blockexplorer.com/tx/send  
https://www.smartbit.com.au/txs/pushtx

## 2of3 Recovery
In the case of 2of3 accounts the user holds the mnemonics for 2 keys: the
default key used for day to day spending and a backup key used for recovery.
Funds held in a 2of3 account can be spent either by signing with the user's
default key and the GreenAddress key (default operation) or by signing with
both the user's default and backup keys (recovery).

Unlike 2of2 where GreenAddress sends nlocktime transactions to the user for
recovery, unspent transaction outputs in 2of3 subaccounts are only discoverable
by scanning the blockchain to look for them. To facilitate this the recovery
tool connects to a full bitcoin node.

You will need:

1) A bitcoin full-node configured for local rpc access  
2) The recovery tool  
3) Your GreenAddress mnemonic  
4) The GreenAddress mnemonic for your 2of3 account  
5) The GreenAddress extended public key (xpub) for your 2of3 account  
6) A destination bitcoin address to send the recovered funds to

Setting up and running a bitcoin full-node is beyond the scope of this document
but instructions are readily available online. Ensure your full node is running
and you are able to connect to the RPC interface. You can verify your full-node
is running before starting by running the bitcoin-cli utility that comes with
bitcoind. Also note that wallet functionality must be enabled.

Run the recovery tool in 2of3 mode:
```
$ garecovery-cli 2of3 --destination-address=XXXX -o garecovery.csv
```

The tool will prompt you for your mnemonic, recovery mnemonic and xpub. You
should have noted these details down when you created the 2of3 subaccount.

The tool will now connect to your bitcoin full-node to scan for the 2of3
transactions. This may take quite a long time. You can check progress either by
looking in the bitcoind log file or in the bitcoin GUI.

Finally if any recoverable coins were found the tool will display a summary of
them on the console and write the details to the output csv file ready for
broadcasting.
