# USZ BlueCat provider

This provider is meant to connect the usz developed REST api to the external-dns.

The code is based on coredns implementation.

## build

```bash
make build.push IMAGE=tribock/external-dns
```

## run

```bash
./build/external-dns --txt-owner-id my-cluster-id --provider uszbluecat --source service --once --dry-run --log-level debug
```


## Current State

The Code is under construction.

No requests are made to any othe components.
Only log is printed.