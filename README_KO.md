# 패킷 감지기 — Suricata 소스 일부 추출판

첨부된 `suricata-main.zip`에서 **패킷 크기(dsize), ICMP 유형(itype), ICMP 코드(icode)**를 비교하는 원본 함수 세 개를 수정 없이 추출하고, 독립 실행에 필요한 입력·규칙 처리·빈도 집계·출력 코드를 연결했습니다.

`bin/packet-detector`가 이미 컴파일된 **Linux x86-64 실행파일**입니다. 이 파일을 실행하는 데 Suricata, Python, Rust, libpcap 설치가 필요하지 않습니다. 명령행에서 사용하는 프로그램이며, Windows에서 더블클릭하는 `.exe`는 아닙니다. Windows를 사용한다면 Ubuntu/Kali 가상머신에서 실행하십시오.

**이 프로그램은 Suricata 전체 탐지 엔진을 분리한 제품이 아니라, 원본 일부를 추출·이식한 실험용 탐지기입니다.** 임의의 Suricata 규칙을 모두 처리하지 않습니다. 지원하지 않는 규칙을 넣으면 시작 단계에서 오류를 냅니다. 전체 Suricata와 탐지율·성능이 같다는 의미도 아닙니다.

## 1. 다운로드한 뒤 바로 실행하기

압축을 푼 `packet-detector` 디렉터리에서 다음 명령을 실행합니다.

```bash
chmod +x bin/packet-detector
./bin/packet-detector -r samples/demo.pcap -l out-demo
```

`-r`은 저장된 패킷 파일을 읽는 옵션입니다. 관리자 권한이 필요하지 않습니다. `-S`를 생략하면 아래의 기본 크기·빈도 규칙을 사용합니다.

예제의 마지막 출력은 다음과 같습니다.

```text
Packets: 34 | decoded: 34 | skipped: 0 | alerts: 5
Output: out-demo
```

`out-demo/`에 분석 결과가 생깁니다. 같은 이름의 결과 파일이 이미 있으면 덮어쓰지 않으므로, 다시 실행할 때는 `-l out-demo-2`처럼 새 디렉터리를 지정합니다. `-l`을 생략하면 실행 시각과 프로세스 번호를 붙인 디렉터리를 만듭니다.

제공한 샘플은 프로그램 동작을 확인하려고 생성한 데이터입니다. 실제 공격 탐지 정확도를 측정한 데이터가 아닙니다. 패킷별 생성 조건·예상 경보는 `samples/demo-labels.csv`, 요약은 `samples/expected.json`, 실제 실행 결과는 `examples-output/demo/`에 있습니다.

## 2. 실제 인터페이스에서 패킷 받기

먼저 인터페이스 이름을 확인합니다.

```bash
./bin/packet-detector --list-interfaces
```

출력된 이름 중 패킷을 받을 인터페이스로 `eth0`를 바꿔 실행합니다.

```bash
sudo ./bin/packet-detector -i eth0 -S rules/icmp-size-rate.rules -l out-live
```

`Ctrl+C`로 끝내면 요약 파일까지 기록합니다. 30초만 수신하려면 다음처럼 실행합니다.

```bash
sudo ./bin/packet-detector -i eth0 --duration 30 -l out-live-30s
```

Linux 실시간 수신은 `AF_PACKET`을 사용하므로 `sudo` 또는 적절한 `CAP_NET_RAW` 권한이 필요합니다. 컨테이너에서는 root여도 해당 권한이 없으면 수신할 수 없습니다. 패킷이 실제로 그 인터페이스에 도착해야 하며, 다른 가상머신 사이의 통신이 자동으로 보이는 것은 아닙니다. 패킷을 감지기 VM의 IP로 보내거나, 실험 구성에 맞는 미러링 위치에서 수신하십시오.

기본값은 들어오는 패킷만 집계합니다. 나가는 관측까지 포함하려면 `--include-outgoing`을 붙입니다. 루프백 등에서 같은 트래픽을 중복 관측할 수 있으므로 빈도 실험에서는 입력 방향을 일정하게 유지하십시오. `--promisc`는 해당 인터페이스에 promiscuous 모드를 요청하며, 스위치의 포트 미러링을 설정하는 기능은 아닙니다.

**검증 범위:** PCAP 입력과 탐지·출력은 실제 실행하여 검증했습니다. 이 제작 환경은 `CAP_NET_RAW`를 제공하지 않으므로 실시간 패킷 수신 자체는 검증하지 못했습니다. 인터페이스 목록 조회와 권한 부족 시 오류 출력은 확인했습니다.

## 3. 기본 탐지 규칙과 정확한 의미

`rules/icmp-size-rate.rules`의 내용입니다.

```text
alert icmp any any -> any any (msg:"Large frequent ICMP echo"; itype:8; dsize:>800; detection_filter:track by_src, count 10, seconds 1; sid:1000001; rev:1;)
```

다음 조건을 모두 적용합니다.

1. IPv4 ICMP 패킷이어야 합니다.
2. `itype:8`이므로 Echo Request여야 합니다.
3. ICMP 데이터 부분이 800바이트보다 커야 합니다. 800바이트는 제외하고 801바이트부터 포함합니다.
4. 위 조건을 충족한 패킷을 출발지 IP별로 집계하여, 1초 시간창 안의 횟수가 10을 초과했을 때 경보를 냅니다.

`dsize`는 Ethernet 프레임 전체 길이나 IP 패킷 전체 길이가 아닙니다. 일반적인 ICMP Echo Request/Reply에서는 8바이트 ICMP 헤더 뒤의 데이터 길이입니다. TCP에서는 TCP 헤더와 옵션 뒤, UDP에서는 UDP 헤더 뒤의 데이터 길이를 사용합니다.

원본 `detection_filter`의 일반 집계 동작에 맞춰 **11번째 조건 충족 패킷부터** 경보를 냅니다. 첫 조건 충족 패킷 시각을 시작으로 하는 고정 시간창이며, 끝점은 포함합니다. 예를 들어 시작 시각이 `100.0초`라면 `101.0초`까지 같은 시간창이고, 그보다 늦은 다음 조건 충족 패킷에서 새 창을 시작합니다. 지속적으로 뒤로 이동하는 sliding window는 아닙니다. 조건에 맞지 않는 작은 패킷이나 Echo Reply는 이 규칙의 빈도에 포함하지 않습니다.

샘플의 34개 중 22개가 유형·크기 조건에 일치하지만, 이 중 충분히 밀집한 요청의 11~15번째인 캡처 번호 23~27에서만 경보가 발생합니다.

크기 조건만 확인하려면 다음 규칙을 사용합니다.

```bash
./bin/packet-detector -r samples/demo.pcap -S rules/icmp-size-only.rules -l out-size-only
```

단순 ICMP·TCP 80번·UDP 53번 관측 예제는 `rules/basic-packets.rules`에 있습니다. 포트 번호가 일치했다는 사실만으로 공격이나 실제 HTTP/DNS 프로토콜이라고 판정하는 것은 아닙니다.

## 4. 지원하는 규칙 문법

기본 형태는 다음과 같습니다.

```text
alert PROTOCOL SOURCE SOURCE_PORT -> DESTINATION DESTINATION_PORT (OPTIONS;)
```

| 항목 | 지원 범위 |
|---|---|
| 동작 | `alert` |
| 프로토콜 | IPv4의 `icmp`, `tcp`, `udp`; `ip`는 이 디코더가 해석한 세 프로토콜을 대상으로 함 |
| 주소 | `any`, IPv4 주소, CIDR, `!IPv4`/`!CIDR` |
| 포트 | `any`, 단일 번호, `1000:2000`, `:1024`, `1024:`, 범위/번호 앞의 `!` |
| 방향 | `->`, `<>` |
| 패킷 조건 | `dsize`, `itype`, `icode` |
| 빈도 | `detection_filter:track by_src 또는 by_dst, count N, seconds S` |
| 식별·표시 | 필수 양수 `sid`, 선택 `msg`, `rev`, `classtype`, `priority`, `reference` |

`msg`, `rev`, `classtype`, `priority`, `reference`는 식별·표시용이며 패킷 내용을 추가로 검사하는 조건이 아닙니다. `classtype`을 Suricata의 classification 파일에 연결해 priority를 자동으로 해석하지는 않습니다. `reference`는 구문을 확인해 받아들이는 출처 메타데이터입니다.

`icmp`와 `ip` 규칙에서는 두 포트 자리에 `any`를 사용합니다. 주소 목록, 포트 목록, `$HOME_NET` 같은 변수는 지원하지 않습니다. 서로 다른 규칙에 같은 `sid`를 사용하면 오류입니다. 최대 256개 규칙을 읽습니다.

정수 조건은 십진수 `n`, `=n`, `!n`, `!=n`, `<n`, `<=n`, `>n`, `>=n`, `a<>b`, `!a<>b`를 지원합니다. 범위 `a<>b`는 양 끝을 제외합니다. 원본 정수 파서가 거부하는 무의미한 경계 비교도 거부합니다. 세부 사항은 `upstream/PROVENANCE.md`에 있습니다.

규칙은 UTF-8 텍스트이며 `#` 주석, 여러 줄 표기, 줄 끝 `\`를 사용할 수 있습니다. 다른 패킷의 상태를 사용하는 `flow`, `flowbits`, 페이로드 검색 `content`, 정규식 `pcre`, `threshold`, `unique_on` 등은 지원하지 않습니다. `by_flow`도 지원하지 않으며, 업로드된 `detection_filter` 파서가 받지 않는 `by_rule`·`by_both`도 거부합니다.

규칙 검사만 하려면 다음 명령을 사용합니다.

```bash
./bin/packet-detector -T -S rules/icmp-size-rate.rules
```

## 5. 결과 파일 읽기

| 파일 | 내용 |
|---|---|
| `packets.csv` | 입력 패킷별 주소·프로토콜·데이터 길이·조건 일치 규칙 수·경보 수·해석 상태 |
| `alerts.csv` | 실제 경보별 패킷 번호·SID·메시지·현재 시간창 내 일치 횟수 |
| `eve.jsonl` | 같은 경보를 줄 단위 JSON으로 기록한 이 프로그램의 형식 |
| `summary.json` | 입력·해석·제외·경보 수, 규칙별 수치, 제외 사유, 실행 상태 |

`packet_index`는 입력된 캡처 레코드의 1부터 시작하는 번호입니다. `timestamp`는 캡처 시각의 Unix epoch 초이며 소수점 이하 9자리까지 기록합니다. 오프라인 빈도 조건은 파일의 이 시각을 사용하며, 프로그램이 파일을 읽는 실제 속도에 의존하지 않습니다. 시각이 역행하는 파일은 오류로 중단합니다.

`matched_packets`는 해당 규칙의 프로토콜·주소·포트·패킷 조건을 통과한 횟수입니다. `alerts`는 빈도 조건까지 적용한 경보 수입니다. 여러 규칙이 같은 패킷에서 경보를 내면 전체 `alerts`는 패킷 수보다 클 수 있습니다. `alerted_packets`는 하나 이상의 경보를 낸 패킷 수입니다. `window_count`가 0이면 해당 규칙에 빈도 필터가 없다는 뜻입니다.

`packets.csv`의 `status=skipped`는 해석 범위 밖이거나 손상·잘림 등으로 검사하지 못한 패킷이며 `reason`을 확인해야 합니다. 이를 정상 판정이나 탐지 실패라고 자동으로 분류하지 마십시오. 추적 상태 한도 초과로 평가가 끝나지 못한 현재 패킷은 `status=error`, `reason=rate_state_capacity`로 남기며 이미 기록한 경보와 패킷 번호 관계를 보존합니다. 실행 도중 오류가 발생한 `summary.json`은 `status=error`인 부분 결과입니다.

이 출력만으로 정답 라벨을 알 수는 없습니다. 탐지율·오탐률을 계산하려면 실제 실험의 패킷/이벤트 정답 라벨과 평가 단위를 별도로 정의해야 합니다. `eve.jsonl`은 일부 익숙한 필드명을 사용하지만 공식 Suricata EVE 전체 스키마와의 호환을 보장하지 않습니다.

## 6. 패킷 입력 범위와 제한

- Classic PCAP 2.4의 little/big endian 및 마이크로초/나노초 시각을 지원합니다.
- Ethernet, VLAN 최대 두 겹, Linux SLL/SLL2, raw IP, NULL/LOOP 링크 형식을 읽습니다.
- IPv4 TCP·UDP와 일부 ICMP 유형을 해석합니다. ICMP 9·13·14번의 확장 헤더 및 지원하지 않는 ICMP 유형은 제외 사유를 기록합니다.
- IPv6, IP 조각 재조립, TCP 스트림 재조립, 터널 해석, HTTP/DNS/TLS 내용 검사, 파일 추출은 포함하지 않습니다.
- 체크섬을 검증하지 않습니다. 손상 체크섬과 캡처 오프로딩에 대한 처리 정책이 전체 Suricata와 다를 수 있습니다.
- 패킷을 차단하지 않습니다. IPS 동작이나 방화벽 설정 변경은 없습니다.
- 한 캡처 레코드는 최대 262,144바이트, 규칙은 최대 256개, 동시에 살아 있는 빈도 집계 상태는 최대 65,536개입니다. 상태가 가득 차면 횟수를 임의로 버리지 않고 오류로 종료합니다.
- 단일 스레드와 규칙 순회 방식입니다. 고속·대용량 운영망 성능은 측정하지 않았습니다.

PCAPNG 파일은 먼저 Classic PCAP으로 변환해야 합니다. Wireshark에 포함되는 `editcap`을 사용할 수 있습니다.

```bash
editcap -F pcap input.pcapng output.pcap
./bin/packet-detector -r output.pcap -l out-converted
```

`-c 100`을 붙이면 100개 입력 레코드를 처리한 뒤 종료합니다. `--quiet`는 개별 콘솔 경보를 줄이며 CSV·JSON 기록은 계속합니다. 전체 옵션은 `--help`로 확인합니다.

## 7. 어떤 소스를 추출했는가

| 원본 | 처리 |
|---|---|
| `src/detect-dsize.c`의 `DetectDsizeMatch` | 함수 정의를 수정 없이 추출 |
| `src/detect-itype.c`의 `DetectITypeMatch` | 함수 정의를 수정 없이 추출 |
| `src/detect-icode.c`의 `DetectICodeMatch` | 함수 정의를 수정 없이 추출 |
| `rust/src/detect/uint.rs`의 `detect_match_uint` | 비교식을 C로 이식 |
| `src/detect-engine-threshold.c`의 일반 `TYPE_DETECTION` 분기 | 시간창·초과 횟수 판정 동작을 이식 |
| 패킷 입력, 디코더, 규칙 파서, 상태 테이블, CLI, 출력 | 독립 실행을 위해 새로 작성 |

실제 원본 함수는 `src/suricata_matchers.inc`, 연결 계층은 `src/predicates.c`, 빈도 처리는 `src/main.c`의 `rate_check`에 있습니다. 비교용 원본 파일, SHA-256 목록, 변경 범위는 `upstream/`에 포함했습니다. ZIP에 정확한 커밋 메타데이터가 없으므로 upstream 버전은 `9.0.0-dev`와 업로드 파일 해시로만 표시합니다.

전체 엔진은 C 코드뿐 아니라 Rust, 패킷·연결 상태, 규칙 관리, 프리필터, 프로토콜 분석 등에 의존합니다. 이 패키지는 그 전체를 가져오지 않고 위의 명시된 판정 기능을 독립 실행하도록 만든 것입니다.

## 8. 빌드와 재검증

실행만 할 때는 이 단계가 필요하지 않습니다. 소스를 바꾸어 다시 빌드할 때 GCC와 make를 사용합니다.

```bash
make
```

동등한 직접 컴파일 명령입니다.

```bash
gcc -Iinclude -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -static \
  -o bin/packet-detector \
  src/main.c src/rules.c src/predicates.c src/decode.c src/capture.c
```

배포 실행파일은 Ubuntu 24.04의 GCC 13.3으로 빌드한 정적 Linux x86-64 ELF입니다. `-march=native`를 사용하지 않았습니다. 다른 아키텍처에서는 해당 환경의 C 컴파일러로 빌드해야 합니다. 정적 C 라이브러리 개발 파일이 없는 환경은 그 파일을 먼저 설치하거나, 직접 명령에서 `-static`을 빼고 로컬 동적 빌드를 할 수 있습니다.

Python 3가 있다면 원본 추출과 동작을 재검증할 수 있습니다. 외부 Python 패키지는 필요하지 않습니다.

```bash
make check
make sanitize
```

`make sanitize`는 AddressSanitizer·UndefinedBehaviorSanitizer용 실행파일을 별도로 만듭니다. 이 환경에서는 LeakSanitizer를 사용할 수 없어 누수 검사를 끄며, 누수까지 검증했다는 뜻은 아닙니다. 실제 검사 목록과 결과는 `tests/VERIFICATION.txt`를 참조하십시오. 실시간 캡처 검증과 PCAP 분석 검증을 구분해 기록했습니다.

## 9. 라이선스와 소스 제공

프로그램의 추출·수정·추가 코드는 GPL-2.0-only로 제공합니다. 원본 OISF 저작권 고지와 GPL 전문 `COPYING`, 수정 가능한 전체 소스, 재빌드 명령을 함께 제공합니다. 정적 링크에 사용한 시스템 런타임의 고지는 `licenses/`에 있습니다.

원본 소스의 추가 설명과 해시 검증 방법은 `upstream/PROVENANCE.md`, 파일별 해시는 `SHA256SUMS.txt`를 확인하십시오.
