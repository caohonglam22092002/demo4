# Digital Forensics Artifact-Collection System
포렌식 아티펙트 수집 시스템<br><br>

다운로드 링크 (Download Link)<br>
https://drive.google.com/file/d/1NjqOMB9WTus6Om0WK08850V9QUdEE2yV/view
<br>
<br>
개발 목적 <br>
디지털 포렌식이 필요한 환경에서 별도의 추가 프로그램 설치 없이 한개의 파일을 통해 포렌식 수사정보 획득
<br>

프로그램 실행 시 다음과 같은 아티펙트 정보 수집
<br>

## 수집 가능한 아티펙트 목록
1. Prefetch
2. NTFS 아티팩트
3. 시스템 정보
4. 레지스트리 하이브
5. 이벤트 뷰어 로그
6. SRUM, Hosts 및 서비스
7. 환경 변수
8. 패치 리스트
9. 실행 프로세스 목록 정보
10. 연결 정보 (열려진 포트)
11. IP 설정 정보
12. ARP 정보
13. NetBIOS 정보
14. 열려있는 핸들 정보
15. 작업 스케줄 정보
16. 시스템 로그온 정보
17. 등록된 서비스 정보
18. UserAssist
19. AutoRun
20. 브라우저 기록
21. 휴지통
22. 파워쉘 로그
23. 최근 LNK 파일

<br>

## 프로그램 사용 방법
1. 위의 다운로드 링크에서 압축파일을 다운로드 받는다.
   ![image](https://github.com/DaeHOHoHOHo/OSS_Project/assets/112150244/6d290fb9-acef-4a68-99dd-2dff809a6663)
   <br><br>
2. 해당 파일을 압축 해제하고 '아티팩트 수집 도구/dist/artifacts.exe 를 관리자권한으로 실행한다.
   ![image](https://github.com/DaeHOHoHOHo/OSS_Project/assets/112150244/f4481a80-c5de-4e2a-a6e1-f44397e15afc)
   <br><br>
3. 수집하기 원하는 아티팩트를 체크 후 저장경로를 설정, 캡쳐 시작 버튼을 누른다. (캡쳐된 파일 분리를 원한다면 케이스 번호에 원하는 값을 입력)
   ![image](https://github.com/DaeHOHoHOHo/OSS_Project/assets/112150244/1cef6136-5f09-4c91-b71b-cb9024a4cd5a)
   <br><br>
4. 캡쳐 시작 버튼을 누르면 위에서 설정한 경로에 해당 아티팩트 수집 결과가 csv 파일 형태로 출력된다.
   ![image](https://github.com/DaeHOHoHOHo/OSS_Project/assets/112150244/0c8bfa13-e60b-466a-b6f5-ff3d2877b3f1)

