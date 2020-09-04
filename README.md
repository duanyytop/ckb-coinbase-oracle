# ckb-open-oracle-script

CKB open oracle lock script

The [open oracle](https://github.com/compound-finance/open-oracle) is a standard and SDK allowing reporters to sign key-value pairs (e.g. a price feed) that interested users can post to the blockchain. The system has a built-in view system that allows clients to easily share data and build aggregates (e.g. the median price from several sources).

## Build

```sh
git submodule init
git submodule update
make clean
make all-via-docker
```
