# pingcert

**English: [README.md](README.md)**

`pingcert`는 DNS, 목적지 도달성, 경로 추적, TCP 연결, TLS 협상, 인증서
정책을 줄 단위로 진단하는 CLI입니다. 텍스트 출력은 장애 로그에 바로 붙일
수 있고, 버전이 지정된 JSON/NDJSON 출력은 자동화에 사용할 수 있습니다.

> 본인이 소유했거나 테스트 권한을 받은 시스템과 네트워크에만 사용하십시오.
> 결과를 공유할 때는 호스트명, IP 주소, 인증서 정보를 가리십시오.

## 왜 pingcert인가

`ping`만으로는 DNS, TCP, TLS, 인증서 중 어느 단계가 실패했는지 알 수 없고,
ICMP를 차단하는 네트워크도 많습니다. `pingcert check`는 애플리케이션 연결에
필요한 검사를 함께 실행하며 TCP, TLS, 인증서 검사가 성공했다면 ping/trace
실패를 경고로 처리합니다.

- `check`: DNS + TCP/TLS/인증서 + 병렬 ping/trace
- `cert`: DNS + TCP/TLS/인증서
- `ping`: DNS + 목적지 ping
- `trace`: DNS + 경로 추적

## 빌드

TLS 및 인증서 파싱 경로의 보안 수정이 포함된 Go 1.26.6 이상이 필요하며 Go
표준 라이브러리만 사용합니다.

직접 설치하려면 다음을 실행하십시오.

```sh
go install github.com/drvoss/pingcert@latest
```

또는 로컬 clone에서 빌드하십시오.

```sh
go test ./...
go build -o pingcert .
```

Windows에서는 `go build -o pingcert.exe .`를 사용하십시오.

## 빠른 시작

```sh
pingcert example.com
pingcert check example.com:443
pingcert cert --warn-before 720h example.com
pingcert ping -4 --count 4 example.com
pingcert trace --max-hops 20 example.com
pingcert --format json --no-trace example.com
pingcert cert --format ndjson --server-name example.com 192.0.2.10
```

대상에는 호스트명, `host:port`, IPv6 리터럴, HTTPS URL을 사용할 수 있으며
기본 포트는 443입니다. 전체 플래그는 `pingcert --help`로 확인하십시오.

## 출력

- `text`: 사람이 읽는 스트리밍 출력
- `json`: 종료 시 출력하는 스키마 버전 지정 보고서
- `ndjson`: 단계가 끝날 때마다 출력하는 스키마 버전 지정 이벤트

명령 기반 ping/traceroute는 항상 `backend=command degraded=true`로
표시합니다. 중간 홉의 무응답만으로 필터링이나 전달 손실을 단정하지 않습니다.

## 인증서 정책

기본 경고 기준은 30일(`720h`)입니다. `--warn-before`로 변경하고,
`--fail-before`로 만료 임박을 실패로 만들 수 있습니다. 인증서 체인, 호스트명,
유효기간, issuer, subject, SHA-256 fingerprint를 확인합니다. 이름 기반 TLS
가상 호스트에 IP로 연결할 때는 `--server-name`을 사용하십시오.

## 종료 코드

| 코드 | 의미 |
|---:|---|
| `0` | 필수 검사 통과. 경고는 남을 수 있음 |
| `1` | 대상, TLS 또는 인증서 정책 실패 |
| `2` | 잘못된 인자 |
| `3` | 로컬 백엔드 또는 출력 실패 |
| `130` | 사용자 중단 |

`check` 모드에서는 DNS, TCP, TLS, 인증서 검사가 필수입니다. ICMP가 흔히
차단되므로 ping과 trace 실패는 경고로 기록합니다.

## 플랫폼 참고사항과 한계

- ping과 traceroute는 플랫폼 명령(`ping`, `tracert`, `traceroute`)을
  실행하므로 세부 동작과 권한은 운영체제에 따라 다릅니다.
- 영어·한글 Windows ping 출력의 대표 픽스처는 있지만 모든 locale 변형을
  검증한 것은 아닙니다.
- 전체 실행 제한은 기본 10초입니다. hop/count가 크면
  `--overall-timeout`도 함께 늘려야 합니다.
- 모니터링 데몬이나 부하 테스트 도구가 아니라 단일 진단 스냅샷 도구입니다.
- JSON 스키마 버전 `1`은 pre-1.0이며 이후 변경될 수 있습니다.

## 개발

```sh
gofmt -w .
go vet ./...
go test ./...
```

테스트는 로컬 데이터와 실행 중 생성하는 인증서를 사용하며 공용 네트워크가
필요하지 않습니다. [CONTRIBUTING.md](CONTRIBUTING.md)와
[SECURITY.md](SECURITY.md)를 참고하십시오.

## 라이선스

MIT — [LICENSE](LICENSE) 참고.
