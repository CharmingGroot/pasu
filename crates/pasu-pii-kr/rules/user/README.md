# 사용자 규칙

여기에 `*.yaml` 을 두면 `default/` 보다 **먼저** 평가된다.
업그레이드해도 이 디렉터리는 덮어쓰지 않는다.

예외를 만들려면 `action: allow` 를 쓴다.

```yaml
rules:
  # 테스트 픽스처로 쓰는 번호는 통과시킨다
  - id: allow-test-fixture
    pattern: '000000-0000000'
    action: allow
```
