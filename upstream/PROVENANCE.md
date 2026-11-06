# 원본 출처와 추출 범위

이 프로그램은 사용자가 제공한 `suricata-main.zip`의 일부 패킷 판정 함수를
추출하여 독립 실행용 입력·규칙 처리 코드에 연결한 실험용 프로그램입니다.
**Suricata 전체 엔진이나 전체 규칙 문법을 제공하는 프로그램이 아닙니다.**

원본 프로젝트: [Suricata / OISF](https://github.com/OISF/suricata)

원본 파일은 `suricata/` 아래에 수정 없이 보관했습니다. 업로드된 ZIP에는 이
사본의 정확한 Git 커밋을 확정할 메타데이터가 없으므로 커밋 번호를 추정하지
않습니다. `manifest.json`에 ZIP 전체와 각 원본 파일의 SHA-256을 기록했습니다.

## 그대로 추출하여 컴파일하는 함수

| 원본 파일 | 함수 | 이 프로그램에서의 역할 |
|---|---|---|
| `suricata/src/detect-dsize.c` | `DetectDsizeMatch` | 디코딩된 전송 계층 페이로드 길이 비교 |
| `suricata/src/detect-itype.c` | `DetectITypeMatch` | ICMP 메시지 종류 비교 |
| `suricata/src/detect-icode.c` | `DetectICodeMatch` | ICMP 코드 비교 |

세 함수의 정의는 함수 이름부터 마지막 중괄호까지 변경하지 않고
`../src/suricata_matchers.inc`에 넣었습니다. 각각의 원본 저작권·GPL 고지도
함께 유지했습니다. 원본의 다른 등록 함수, 프리필터, 시그니처 관리 코드는
포함하지 않았습니다.

`../src/predicates.c`의 작은 호환 계층은 원본 함수가 기대하는 `Packet`,
정수 조건 타입, 접근 매크로, 로그 매크로를 제공합니다. `PacketView`의
페이로드 길이·IP 버전·프로토콜·ICMP type/code를 이 구조에 옮깁니다.
엔진과 시그니처 문맥 포인터는 이 세 함수에서 사용하지 않습니다. 실제 입력은
캡처된 패킷이며 Suricata 내부의 가상 패킷은 생성하지 않습니다.

## 번역·참조하거나 새로 작성한 부분

| 구성 요소 | 출처와 변경 내용 |
|---|---|
| `predicate_match` | `suricata/rust/src/detect/uint.rs`의 `detect_match_uint`를 C로 번역했습니다. 10개 비교 방식의 판정식을 유지했습니다. |
| `predicate_parse` | 새로 작성한 제한된 십진수 파서입니다. 원본 Rust 파서를 가져온 것이 아닙니다. 지원하지 않는 문법은 오류로 처리합니다. |
| `DetectU8Match`, `DetectU16Match` 호환 함수 | 원본 `suricata/src/detect-engine-uint.c`는 Rust FFI를 호출합니다. 여기서는 위 C 비교 함수에 연결합니다. |
| 빈도 조건 | `suricata/src/detect-engine-threshold.c`의 일반 `TYPE_DETECTION` 시간창·횟수 조건을 참조합니다. 원본의 해시테이블·스레드·테넌트·포트 비트맵 전체를 가져온 것이 아닙니다. |
| 디코더와 캡처 입력 | 독립 실행을 위해 새로 작성한 코드입니다. `suricata/src/decode-icmpv4.c`를 함께 제공하여 ICMP 페이로드 범위를 확인할 수 있습니다. |
| 규칙 읽기, 실행 명령, 상태 관리, 결과 출력 | 이 프로그램용으로 새로 작성한 코드입니다. Suricata 전체 구현의 축약본이라는 뜻은 아닙니다. |

### 정수 조건의 범위

문자열 파서는 십진수 `n`, `=n`, `!n`, `!=n`, `<n`, `<=n`, `>n`, `>=n`,
`a<>b`, `!a<>b`를 지원합니다. `dsize`는 0..65535, `itype`와 `icode`는
0..255 범위입니다. `a<>b`는 `a < 값 < b`이며 양쪽 끝을 포함하지 않습니다.
따라서 범위 안에 정수가 하나 이상 있어야 합니다(`b > a + 1`).

원본 파서처럼 `<0`, `>최댓값`, `<=최댓값`, `>=0`은 거부합니다. 16진수,
단위 접미사, `a-b` 범위 표기, 비트마스크 문자열은 지원하지 않습니다.
비트마스크 판정 자체는 원본 정수 비교 함수를 충실히 옮기기 위해 C 함수에
남겨 두었지만 규칙 문자열로 지정할 수 없습니다.

### 빈도 조건을 읽을 때 주의할 의미

기본 `detection_filter`의 `count N, seconds S`는 이미 나머지 규칙을
충족한 패킷을 추적합니다. 첫 해당 패킷부터 시작한 고정 시간창 안에서 횟수가
N을 **초과**한 N+1번째부터 경보가 발생합니다. `시작 시각 + S초`의 정확한
끝점은 기존 시간창에 포함됩니다. 움직이는 시간창 방식이 아닙니다.

원본의 이 동작은 `suricata/src/detect-detection-filter.c`에도 검증 사례가
있습니다. `unique_on`이나 다른 threshold 종류의 의미까지 제공하는 것은
아닙니다. 이 구현의 지원 범위는 최상위 사용 설명서를 확인하십시오.

## 추출 결과 재현 및 검증

프로젝트 최상위에서 Python 3 표준 라이브러리만으로 실행할 수 있습니다.

```bash
python3 tools/extract_upstream.py --verify
```

이 명령은 10개 원본 파일의 SHA-256, 세 함수의 SHA-256 및 추출 파일 전체를
검사합니다. 원본 파일을 변경하지 않은 상태에서 다음 명령으로 추출 파일을
재생성할 수 있습니다.

```bash
python3 tools/extract_upstream.py
```

사용자가 처음 올린 소스 디렉터리와 직접 대조하려면 다음과 같이 실행합니다.

```bash
python3 tools/extract_upstream.py --verify --source-dir /path/to/suricata-main
```

추출기는 주석·문자열·문자 상수 안의 중괄호를 제외하고 실제 함수 경계를
계산합니다. 선언문만 찾거나 단순히 첫 번째 `}`에서 끊지 않습니다.

## 라이선스

보관한 원본과 추출·번역 코드는 GPL-2.0-only입니다. Open Information
Security Foundation의 원본 저작권 고지를 유지했습니다. 원본 GPL 전문은
`suricata/COPYING`과 `suricata/LICENSE`에 있습니다. 이 패키지에는 실행파일을
재생성하는 데 필요한 새 소스와 빌드 방법도 함께 제공합니다.

원본 출처와 일부 판정식이 같다는 사실은 전체 Suricata의 탐지율·성능과
동일함을 뜻하지 않습니다. 이 실행파일의 결과는 이 프로그램의 명시된
패킷 규칙 부분집합에 대한 결과로 기록해야 합니다.
