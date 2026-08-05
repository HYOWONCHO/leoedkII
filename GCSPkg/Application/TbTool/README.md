# 🧩 TB Tool Overview (SBC Boot Firmware & AT-SW Integration Test Tool)

본 Tool은 **SBC 부트펌웨어 및 AT-SW 연동 테스트와 테스트 조건 구축**을 위해 사용됩니다.  
SBC 부트펌웨어와 AT-SW 간 연동을 검증하고, 테스트 환경을 손쉽게 구성할 수 있도록 지원합니다.

---

## 📘 주요 기능 요약

### 1. Raw Partition 데이터 시각화
- Raw Partition 데이터를 **Hexdump 형식**으로 출력하여 디버깅 및 데이터 구조 분석에 활용

### 2. Boot Firmware 저장 기능
- Boot Firmware를 Raw Partition 지정 영역에 **Write**하여 부팅 구성 데이터를 저장

### 3. 부팅 상태 및 설정 관리
- 시스템 부트 상태 조회  
- 부팅 과정에서 사용하는 주요 설정들을 관리

### 4. 시스템 모드 설정 지원
- System Boot Mode & Key Mode 관련 Configuration 제공 및 변경 가능

---

# 🛠 Command Usage & Description

아래 명령어들은 테스트베드(TB) 환경에서 SBC Boot FW 및 AT-SW 연동 테스트를 수행하는 데 사용됩니다.

---

## 📌 `--dumpimg`  
지정된 Raw Partition 영역을 읽어 **Hexdump 형식으로 시각화 출력**합니다.

### **Usage**
```bash
./tb_tool --dumpimg <device_path> <hex_addr> <size>
```
## 📌 `--loadimg`  
Raw Partition 영역에 부트 펌웨어 또는 바이너리를 Write하여 부팅 구성 데이터를 업데이트합니다.

### **Usage**
```bash
./tb_tool --loadimg <device_path> <file> <hex_addr> <size>
```
