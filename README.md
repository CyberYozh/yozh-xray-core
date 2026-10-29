# yozh-xray-core

The network engine of the CyberYozh proxy clients: a fork of
[Xray-core](https://github.com/XTLS/Xray-core) by Project X, version v26.7.28.

This repository holds the exact source of the engine each client ships. There is one snapshot
per platform, and the fork's history is not included:

| Branch    | Platform                |
|-----------|-------------------------|
| `main`    | macOS (darwin/arm64)    |
| `windows` | Windows (windows/amd64) |

Each new engine version replaces the snapshot on its branch. A snapshot is one commit without
parents, and its message names the fork commit it was cut from.

## License

This fork uses the Mozilla Public License 2.0, the same as Xray-core: see [LICENSE](LICENSE).
Xray-core, its documentation and its community are at https://github.com/XTLS/Xray-core. To
support the Xray-core project, use the links there.

## Changes from Xray-core v26.7.28

Removed:

- **Shadowsocks 2022,** with the `sagernet` libraries it depends on (`proxy/shadowsocks_2022`,
  `common/singbridge`). Shadowsocks with AEAD ciphers is still supported.
- **The Windows process finder** (`common/net/find_process_windows.go`). Routing rules by
  process name have no effect on Windows; the Windows client tells programs apart itself.
- **The `pprof` profiler** on the metrics listener. The listener serves counters only.

Written again independently:

- **The parts that came from another project:**
  - in the TUN inbound: the gVisor stack bridge, the Wintun and file-descriptor endpoints,
    the macOS route and address setup, and the ICMP checksum;
  - in WireGuard: the choice of a free interface name.

Changed:

- **UDP in TUN is routed per destination.** A socket's first destination no longer decides
  where all its later datagrams go, and the number of flows from one source is bounded.
- **A UDP flow that the sniffer named** is routed by that name. Its outbound still receives the
  address the program used.
- **Counters:** TUN counts connections, and bytes per network.
- **Connection end:** the engine can report the end of each connection to the client, through a
  webhook routing rule that asks for it.
- **Windows only (`windows`):** Wintun's adapter is closed only after its readers have stopped.
- **macOS only (`main`):**
  - routing by application. A `process` entry `yozh:rule-<N>`, `yozh:unresolved` or
    `yozh:nolocal` is a label, not a process name: the engine asks the client's routing
    resolver, over the unix socket named in `YOZH_ROUTING_SOCKET`, which of the client's rules
    the connection's program falls under. The engine talks only to a resolver of its own user
    (it reads the listener's credentials, `LOCAL_PEERCRED`), and a config with such labels does
    not start without one;
  - two Darwin fixes merged upstream after v26.7.28:
    [XTLS/Xray-core#6557](https://github.com/XTLS/Xray-core/pull/6557) (`process` rules and
    IPv4-mapped sockets) and [XTLS/Xray-core#6580](https://github.com/XTLS/Xray-core/pull/6580)
    (the TUN reader waits on kqueue instead of spinning).

## Building

The build is reproducible: built as below, a snapshot gives the client's engine byte for byte,
before the client signs it.

```sh
git clone https://github.com/CyberYozh/yozh-xray-core.git
cd yozh-xray-core
git checkout windows                 # or: main
mkdir ../src
git -c core.autocrlf=false archive 'HEAD^{tree}' | tar -x -C ../src
cd ../src
env -i PATH="$PATH" HOME="$HOME" GOENV=off GOTOOLCHAIN=go1.26.7 \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false \
    -ldflags "-X github.com/xtls/xray-core/core.build=<commit>" \
    -o yozh-xray.exe ./main
sha256sum yozh-xray.exe
```

`-c core.autocrlf=false` matters on Windows: Git for Windows converts line endings on export by
default, and an engine built from converted files differs from the client's.

`<commit>` is the first seven characters of the fork commit named in the snapshot's commit
message. For macOS, use `GOOS=darwin GOARCH=arm64 GOARM64=v8.0`, `-o yozh-xray` and `shasum -a 256 yozh-xray` instead.
Each client records the SHA-256 it expects in its `tools/xray-fork/engine.lock`.
