//! YAML 규칙 파일 로딩 (feature = "yaml").
//!
//! `default/`(프로젝트 제공, 업그레이드 시 덮어씀)와 `user/`(사용자 커스텀, 보존)를
//! 나눠 두고, 사용자 규칙을 앞에 놓아 먼저 평가되게 한다.

use std::path::Path;

use crate::{rule::Rule, Error, Filter};

#[derive(serde::Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

impl Filter {
    /// YAML 문자열에서 규칙을 읽는다.
    ///
    /// # Errors
    /// 해석 실패, 잘못된 정규식, 알 수 없는 검증기.
    pub fn from_yaml(yaml: &str) -> Result<Self, Error> {
        let parsed: RuleFile =
            serde_yml::from_str(yaml).map_err(|e| Error::Config(e.to_string()))?;
        Self::from_rules(parsed.rules)
    }

    /// 디렉터리에서 규칙을 읽는다. `<dir>/user/*.yaml` 이 `<dir>/default/*.yaml` 보다
    /// 먼저 평가되므로, 사용자 규칙으로 예외(`action: allow`)를 만들 수 있다.
    ///
    /// 각 디렉터리 안에서는 파일 이름 순으로 읽는다(`rules.d` 관례).
    ///
    /// # Errors
    /// 디렉터리를 읽을 수 없거나 규칙이 잘못된 경우.
    pub fn from_dir(dir: &Path) -> Result<Self, Error> {
        let mut rules = Vec::new();
        for sub in ["user", "default"] {
            let path = dir.join(sub);
            if !path.is_dir() {
                continue;
            }
            let mut files: Vec<_> = std::fs::read_dir(&path)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
                .collect();
            files.sort();

            for f in files {
                let text = std::fs::read_to_string(&f)
                    .map_err(|e| Error::Config(format!("{}: {e}", f.display())))?;
                let parsed: RuleFile = serde_yml::from_str(&text)
                    .map_err(|e| Error::Config(format!("{}: {e}", f.display())))?;
                rules.extend(parsed.rules);
            }
        }
        Self::from_rules(rules)
    }
}
