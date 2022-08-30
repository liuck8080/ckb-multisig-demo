# ckb-multisig-demo

This is a copy of the repository of git@github.com:liuck8080/ckb-multisig.git, just to write the rust_multisig.pptx.
Build contracts:

``` sh
git submodule add https://github.com/nervosnetwork/ckb-production-scripts.git contracts/ckb-multisig/ckb-lib-secp256k1/ckb-production-scripts
git submodule update --init --recursive
make -C contracts/ckb-multisig/ckb-lib-secp256k1/ all-via-docker
capsule build
```

Run tests:

``` sh
cd orig-tests/sepcs/cells/ && ln -s ../../../target/riscv64imac-unknown-none-elf/debug/ckb-multisig-demo . && cd -
cd orig-tests/
cargo test
```
