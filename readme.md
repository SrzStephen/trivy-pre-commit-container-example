# Trivy Scanning Example

## About
Super basic example of how to get basic docker container scanning working as part of your pre-commit pipeline.

All that you need is in one `.pre-commit-config.yaml`


## Installation
Untested on non Debian/Ubuntu
* Install [docker](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)
  * Ensure that your current user is added to the [Docker group](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user)
* Install [Homebrew](https://brew.sh/)
* Install [Trivy with Homebrew](https://aquasecurity.github.io/trivy/v0.18.3/installation/#homebrew)
* Install [pre-commit](https://pre-commit.com/)

## Use
```
rm -rf .git
git init
pre-commit install
git add .pre-commit-config.yaml Dockerfile readme.md
git commit -m "first commit"
```

## Results

### Configuration
```
Trivy configuration issue................................................Failed
- hook id: trivy-config
- exit code: 1

2024-01-16T20:41:05.580+0800    INFO    Misconfiguration scanning is enabled
2024-01-16T20:41:06.299+0800    INFO    Detected config files: 1

Dockerfile (dockerfile)

Tests: 19 (SUCCESSES: 18, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

HIGH: Specify at least 1 USER command in Dockerfile with non-root user as argument
════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
────────────────────────────────────────
```
### CVE
```
Trivy Critical CVE scan..................................................Failed
- hook id: trivy-cve-critical-high
- exit code: 1

2024-01-16T20:41:03.272+0800    INFO    Vulnerability scanning is enabled
2024-01-16T20:41:04.872+0800    INFO    Detected OS: alpine
2024-01-16T20:41:04.872+0800    INFO    Detecting Alpine vulnerabilities...
2024-01-16T20:41:04.873+0800    INFO    Number of language-specific files: 2
2024-01-16T20:41:04.873+0800    INFO    Detecting gobinary vulnerabilities...
2024-01-16T20:41:04.884+0800    WARN    This OS version is no longer supported by the distribution: alpine 3.11.6
2024-01-16T20:41:04.884+0800    WARN    The vulnerability detection may be insufficient because security updates are not provided

scan:latest (alpine 3.11.6)

Total: 37 (HIGH: 32, CRITICAL: 5)

┌──────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬──────────────────────────────────────────────────────────────┐
│   Library    │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                            Title                             │
├──────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ apk-tools    │ CVE-2021-36159 │ CRITICAL │ fixed  │ 2.10.5-r0         │ 2.10.7-r0     │ libfetch: an out of boundary read while libfetch uses strtol │
│              │                │          │        │                   │               │ to parse...                                                  │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-36159                   │
│              ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-30139 │ HIGH     │        │                   │ 2.10.6-r0     │ In Alpine Linux apk-tools before 2.12.5, the tarball parser  │
│              │                │          │        │                   │               │ allows a buffer...                                           │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-30139                   │
├──────────────┼────────────────┤          │        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ busybox      │ CVE-2021-28831 │          │        │ 1.31.1-r9         │ 1.31.1-r10    │ invalid free or segmentation fault via malformed gzip data   │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-28831                   │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42378 │          │        │                   │ 1.31.1-r11    │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42378                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42379 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42379                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42380 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42380                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42381 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42381                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42382 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42382                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42383 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42383                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42384 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42384                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42385 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42385                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42386 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42386                   │
├──────────────┼────────────────┤          │        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ krb5-libs    │ CVE-2020-28196 │          │        │ 1.17.1-r0         │ 1.17.2-r0     │ krb5: unbounded recursion via an ASN.1-encoded Kerberos      │
│              │                │          │        │                   │               │ message in lib/krb5/asn.1/asn1_encode.c may lead...          │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2020-28196                   │
├──────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ libcrypto1.1 │ CVE-2021-3711  │ CRITICAL │        │ 1.1.1g-r0         │ 1.1.1l-r0     │ SM2 Decryption Buffer Overflow                               │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3711                    │
│              ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-23840 │ HIGH     │        │                   │ 1.1.1j-r0     │ integer overflow in CipherUpdate                             │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-23840                   │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3450  │          │        │                   │ 1.1.1k-r0     │ openssl: CA certificate check bypass with                    │
│              │                │          │        │                   │               │ X509_V_FLAG_X509_STRICT                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3450                    │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3712  │          │        │                   │ 1.1.1l-r0     │ openssl: Read buffer overruns processing ASN.1 strings       │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3712                    │
├──────────────┼────────────────┤          │        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ libgcc       │ CVE-2019-15847 │          │        │ 9.2.0-r4          │ 9.3.0-r0      │ gcc: POWER9 "DARN" RNG intrinsic produces repeated output    │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2019-15847                   │
├──────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ libssl1.1    │ CVE-2021-3711  │ CRITICAL │        │ 1.1.1g-r0         │ 1.1.1l-r0     │ SM2 Decryption Buffer Overflow                               │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3711                    │
│              ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-23840 │ HIGH     │        │                   │ 1.1.1j-r0     │ integer overflow in CipherUpdate                             │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-23840                   │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3450  │          │        │                   │ 1.1.1k-r0     │ openssl: CA certificate check bypass with                    │
│              │                │          │        │                   │               │ X509_V_FLAG_X509_STRICT                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3450                    │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3712  │          │        │                   │ 1.1.1l-r0     │ openssl: Read buffer overruns processing ASN.1 strings       │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3712                    │
├──────────────┼────────────────┼──────────┤        │                   │               ├──────────────────────────────────────────────────────────────┤
│ openssl      │ CVE-2021-3711  │ CRITICAL │        │                   │               │ SM2 Decryption Buffer Overflow                               │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3711                    │
│              ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-23840 │ HIGH     │        │                   │ 1.1.1j-r0     │ integer overflow in CipherUpdate                             │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-23840                   │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3450  │          │        │                   │ 1.1.1k-r0     │ openssl: CA certificate check bypass with                    │
│              │                │          │        │                   │               │ X509_V_FLAG_X509_STRICT                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3450                    │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-3712  │          │        │                   │ 1.1.1l-r0     │ openssl: Read buffer overruns processing ASN.1 strings       │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-3712                    │
├──────────────┼────────────────┤          │        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ ssl_client   │ CVE-2021-28831 │          │        │ 1.31.1-r9         │ 1.31.1-r10    │ invalid free or segmentation fault via malformed gzip data   │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-28831                   │
│              ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42378 │          │        │                   │ 1.31.1-r11    │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42378                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42379 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42379                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42380 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42380                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42381 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42381                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42382 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42382                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42383 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42383                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42384 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42384                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42385 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42385                   │
│              ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│              │ CVE-2021-42386 │          │        │                   │               │ busybox: use-after-free in awk applet leads to denial of     │
│              │                │          │        │                   │               │ service and possibly...                                      │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2021-42386                   │
├──────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ zlib         │ CVE-2022-37434 │ CRITICAL │        │ 1.2.11-r3         │ 1.2.11-r4     │ zlib: heap-based buffer over-read and overflow in inflate()  │
│              │                │          │        │                   │               │ in inflate.c via a...                                        │
│              │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2022-37434                   │
└──────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────────┘

usr/share/grafana/bin/grafana-cli (gobinary)

Total: 8 (HIGH: 8, CRITICAL: 0)

┌─────────────────────────────────────┬────────────────┬──────────┬────────┬────────────────────────────────────┬───────────────────────────────────┬──────────────────────────────────────────────────────────────┐
│               Library               │ Vulnerability  │ Severity │ Status │         Installed Version          │           Fixed Version           │                            Title                             │
├─────────────────────────────────────┼────────────────┼──────────┼────────┼────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ github.com/prometheus/client_golang │ CVE-2022-21698 │ HIGH     │ fixed  │ v1.3.0                             │ 1.11.1                            │ prometheus/client_golang: Denial of service using            │
│                                     │                │          │        │                                    │                                   │ InstrumentHandlerCounter                                     │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-21698                   │
├─────────────────────────────────────┼────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ golang.org/x/crypto                 │ CVE-2020-29652 │          │        │ v0.0.0-20200406173513-056763e48d71 │ 0.0.0-20201216223049-8b5274cf687f │ crafted authentication request can lead to nil pointer       │
│                                     │                │          │        │                                    │                                   │ dereference                                                  │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-29652                   │
│                                     ├────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2021-43565 │          │        │                                    │ 0.0.0-20211202192323-5770296d904e │ empty plaintext packet causes panic                          │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2021-43565                   │
│                                     ├────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-27191 │          │        │                                    │ 0.0.0-20220314234659-1baeb1ce4c0b │ golang: crash in a golang.org/x/crypto/ssh server            │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-27191                   │
├─────────────────────────────────────┼────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ golang.org/x/net                    │ CVE-2021-33194 │          │        │ v0.0.0-20200202094626-16171245cfb2 │ 0.0.0-20210520170846-37e1c6afe023 │ infinite loop in ParseFragment                               │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2021-33194                   │
│                                     ├────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-27664 │          │        │                                    │ 0.0.0-20220906165146-f3363e06e74c │ golang: net/http: handle server errors after sending GOAWAY  │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-27664                   │
│                                     ├────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-41723 │          │        │                                    │ 0.7.0                             │ net/http, golang.org/x/net/http2: avoid quadratic complexity │
│                                     │                │          │        │                                    │                                   │ in HPACK decoding                                            │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-41723                   │
│                                     ├────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-39325 │          │        │                                    │ 0.17.0                            │ golang: net/http, x/net/http2: rapid stream resets can cause │
│                                     │                │          │        │                                    │                                   │ excessive work (CVE-2023-44487)                              │
│                                     │                │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2023-39325                   │
└─────────────────────────────────────┴────────────────┴──────────┴────────┴────────────────────────────────────┴───────────────────────────────────┴──────────────────────────────────────────────────────────────┘

usr/share/grafana/bin/grafana-server (gobinary)

Total: 20 (HIGH: 16, CRITICAL: 4)

┌─────────────────────────────────────┬─────────────────────┬──────────┬────────┬────────────────────────────────────┬───────────────────────────────────┬──────────────────────────────────────────────────────────────┐
│               Library               │    Vulnerability    │ Severity │ Status │         Installed Version          │           Fixed Version           │                            Title                             │
├─────────────────────────────────────┼─────────────────────┼──────────┼────────┼────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ github.com/crewjam/saml             │ CVE-2020-27846      │ CRITICAL │ fixed  │ v0.0.0-20191031171751-c42136edf9b1 │ 0.4.3                             │ authentication bypass in saml authentication                 │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-27846                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-41912      │          │        │                                    │ 0.4.9                             │ crewjam/saml: Authentication bypass when processing SAML     │
│                                     │                     │          │        │                                    │                                   │ responses containing multiple Assertion elements             │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-41912                   │
│                                     ├─────────────────────┼──────────┤        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-28119      │ HIGH     │        │                                    │ 0.4.13                            │ crewjam/saml: Denial Of Service Via Deflate Decompression    │
│                                     │                     │          │        │                                    │                                   │ Bomb                                                         │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2023-28119                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-45683      │          │        │                                    │ 0.4.14                            │ github.com/crewjam/saml: Cross-Site-Scripting (XSS) in       │
│                                     │                     │          │        │                                    │                                   │ github.com/crewjam/saml                                      │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2023-45683                   │
├─────────────────────────────────────┼─────────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ github.com/prometheus/client_golang │ CVE-2022-21698      │          │        │ v1.3.0                             │ 1.11.1                            │ prometheus/client_golang: Denial of service using            │
│                                     │                     │          │        │                                    │                                   │ InstrumentHandlerCounter                                     │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-21698                   │
├─────────────────────────────────────┼─────────────────────┼──────────┤        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ github.com/russellhaering/goxmldsig │ CVE-2020-26290      │ CRITICAL │        │ v0.0.0-20180430223755-7acd5e4a6ef7 │ 1.1.0                             │ Critical security issues in XML encoding in                  │
│                                     │                     │          │        │                                    │                                   │ github.com/dexidp/dex                                        │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-26290                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ GHSA-rrfw-hg9m-j47h │          │        │                                    │ 0.4.2                             │ Signature Validation Bypass                                  │
│                                     │                     │          │        │                                    │                                   │ https://github.com/advisories/GHSA-rrfw-hg9m-j47h            │
│                                     ├─────────────────────┼──────────┤        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2020-7711       │ HIGH     │        │                                    │ 1.1.1                             │ goxmldsig: sending malformed XML signatures could result in  │
│                                     │                     │          │        │                                    │                                   │ a crash                                                      │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-7711                    │
│                                     ├─────────────────────┤          │        │                                    │                                   ├──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2020-7731       │          │        │                                    │                                   │ github.com/russellhaering/gosaml2 is vulnerable to NULL      │
│                                     │                     │          │        │                                    │                                   │ Pointer Dereference                                          │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-7731                    │
│                                     ├─────────────────────┤          │        │                                    │                                   ├──────────────────────────────────────────────────────────────┤
│                                     │ GHSA-gq5r-cc4w-g8xf │          │        │                                    │                                   │ gosaml2 is vulnerable to NULL Pointer Dereference from       │
│                                     │                     │          │        │                                    │                                   │ malformed XML signatures                                     │
│                                     │                     │          │        │                                    │                                   │ https://github.com/advisories/GHSA-gq5r-cc4w-g8xf            │
├─────────────────────────────────────┼─────────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ golang.org/x/crypto                 │ CVE-2020-29652      │          │        │ v0.0.0-20200406173513-056763e48d71 │ 0.0.0-20201216223049-8b5274cf687f │ crafted authentication request can lead to nil pointer       │
│                                     │                     │          │        │                                    │                                   │ dereference                                                  │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2020-29652                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2021-43565      │          │        │                                    │ 0.0.0-20211202192323-5770296d904e │ empty plaintext packet causes panic                          │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2021-43565                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-27191      │          │        │                                    │ 0.0.0-20220314234659-1baeb1ce4c0b │ golang: crash in a golang.org/x/crypto/ssh server            │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-27191                   │
├─────────────────────────────────────┼─────────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ golang.org/x/net                    │ CVE-2021-33194      │          │        │ v0.0.0-20200202094626-16171245cfb2 │ 0.0.0-20210520170846-37e1c6afe023 │ infinite loop in ParseFragment                               │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2021-33194                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-27664      │          │        │                                    │ 0.0.0-20220906165146-f3363e06e74c │ golang: net/http: handle server errors after sending GOAWAY  │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-27664                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-41723      │          │        │                                    │ 0.7.0                             │ net/http, golang.org/x/net/http2: avoid quadratic complexity │
│                                     │                     │          │        │                                    │                                   │ in HPACK decoding                                            │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-41723                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2023-39325      │          │        │                                    │ 0.17.0                            │ golang: net/http, x/net/http2: rapid stream resets can cause │
│                                     │                     │          │        │                                    │                                   │ excessive work (CVE-2023-44487)                              │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2023-39325                   │
├─────────────────────────────────────┼─────────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ golang.org/x/text                   │ CVE-2021-38561      │          │        │ v0.3.2                             │ 0.3.7                             │ golang: out-of-bounds read in golang.org/x/text/language     │
│                                     │                     │          │        │                                    │                                   │ leads to DoS                                                 │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2021-38561                   │
│                                     ├─────────────────────┤          │        │                                    ├───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                                     │ CVE-2022-32149      │          │        │                                    │ 0.3.8                             │ golang: golang.org/x/text/language: ParseAcceptLanguage      │
│                                     │                     │          │        │                                    │                                   │ takes a long time to parse complex tags                      │
│                                     │                     │          │        │                                    │                                   │ https://avd.aquasec.com/nvd/cve-2022-32149                   │
├─────────────────────────────────────┼─────────────────────┤          │        ├────────────────────────────────────┼───────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ google.golang.org/grpc              │ GHSA-m425-mq94-257g │          │        │ v1.27.1                            │ 1.56.3, 1.57.1, 1.58.3            │ gRPC-Go HTTP/2 Rapid Reset vulnerability                     │
│                                     │                     │          │        │                                    │                                   │ https://github.com/advisories/GHSA-m425-mq94-257g            │
└─────────────────────────────────────┴─────────────────────┴──────────┴────────┴────────────────────────────────────┴───────────────────────────────────┴──────────────────────────────────────────────────────────────┘
```
## Comment
Something that tripped me up: 

pre-commit will scan what you are about to commit, this means that if you have made changes to your Dockerfile
and **haven't** added them, then trivy will not be scanning your new changes.