# XDP Compatibility

This crate provides a client-only DNS check for Agave XDP compatibility.
It sends DNS requests over agave-xdp to a public DNS resolver and validates the
responses. If the check fails, there is likely a host/network/XDP issue.

Please report failures in the Solana Discord in `#validator-support`, with:
1) Host details (kernel version, etc)
2) Command you ran
3) Error output
4) Output of `ethtool -i <IFACE>`

## Usage

For XDP zero-copy, the client binary needs extra capabilities. Build it and set caps:
```
cargo build --release -p xdp-compatibility
sudo setcap cap_net_admin,cap_net_raw,cap_bpf,cap_perfmon+ep target/release/xdp-compatibility
```

Then run the built binary directly:
```
./target/release/xdp-compatibility \
  --endpoint-ip <DNS resolver> \
  --experimental-retransmit-xdp-cpu-cores <CORE> \
  --experimental-retransmit-xdp-interface <IFACE> \
  --timeout-ms 1000 \
  --experimental-retransmit-xdp-zero-copy
```

Example: `--endpoint-ip 8.8.8.8` (Google) or `--endpoint-ip 1.1.1.1` (Cloudflare).
