# Omnilock

## Document
See [RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0042-omnilock/0042-omnilock.md)

## Build

```
git submodule update --init
make all-via-docker
```

## Test

```
cd tests/omni_lock_rust && cargo test
```

## Deployment

See [RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0042-omnilock/0042-omnilock.md)


## Test Vector

```shell
#  Project root directory
ckb-debugger --bin build/omni_lock -f test-vectors/tx_btc_P2PKH_compressed.json -i 0 -s lock
```
