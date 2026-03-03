//! Конфигурация flux-server в YAML формате.
//!
//! Минимальный рабочий конфиг:
//! ```yaml
//! server:
//!   listen: "0.0.0.0:4433"
//!
//! tls:
//!   cert: "/etc/flux/cert.pem"
//!   key:  "/etc/flux/key.pem"
//!
//! users:
//!   - name: "alice"
//!     password: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//! ```
//!
//! Всё остальное имеет разумные дефолты.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Ошибки
// ============================================================================

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Cannot read config file '{path}': {source}")]
    ReadFile { path: String, source: std::io::Error },

    #[error("YAML parse error in '{path}': {source}")]
    Parse { path: String, source: serde_yaml::Error },

    #[error("Validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

// ============================================================================
// Структуры конфига
// ============================================================================

/// Корневой конфиг
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub users: Vec<UserConfig>,

    #[serde(default)]
    pub bandwidth: BandwidthConfig,

    #[serde(default)]
    pub log: LogConfig,
}

/// Параметры сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Адрес для прослушивания, например "0.0.0.0:4433"
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Максимум одновременных соединений (0 = без лимита)
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_connections: default_max_connections(),
        }
    }
}

/// TLS сертификаты
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Путь к cert.pem
    pub cert: PathBuf,
    /// Путь к key.pem
    pub key: PathBuf,
}

/// Один пользователь
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Имя пользователя (для логов и идентификации)
    pub name: String,
    /// Пароль — ровно 64 символа hex или любых ASCII
    pub password: String,
}

/// Глобальные лимиты пропускной способности
/// Применяются ко всему серверу суммарно.
/// Для per-user лимитов — добавить поле в UserConfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthConfig {
    /// Лимит исходящего трафика сервера, Mbps (0 = без лимита)
    #[serde(default)]
    pub up_mbps: u64,
    /// Лимит входящего трафика сервера, Mbps (0 = без лимита)
    #[serde(default)]
    pub down_mbps: u64,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self { up_mbps: 0, down_mbps: 0 }
    }
}

/// Настройки логирования
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Уровень: trace / debug / info / warn / error
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Файл для записи логов. None = только stdout.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

// ============================================================================
// Дефолты
// ============================================================================

fn default_listen() -> String        { "0.0.0.0:4433".to_string() }
fn default_max_connections() -> usize { 1024 }
fn default_log_level() -> String     { "info".to_string() }

// ============================================================================
// Загрузка и валидация
// ============================================================================

impl Config {
    /// Загружает конфиг из YAML файла и валидирует его.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadFile {
                path: path.to_string(),
                source: e,
            })?;

        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::Parse {
                path: path.to_string(),
                source: e,
            })?;

        config.validate()?;
        Ok(config)
    }

    /// Загружает конфиг из строки (удобно для тестов).
    pub fn from_str(yaml: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(yaml)
            .map_err(|e| ConfigError::Parse {
                path: "<string>".to_string(),
                source: e,
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Валидация всех полей.
    fn validate(&self) -> Result<()> {
        // server.listen — должен быть валидный SocketAddr
        self.server.listen.parse::<std::net::SocketAddr>()
            .map_err(|_| ConfigError::Validation(
                format!("server.listen '{}' is not a valid address (expected ip:port)", self.server.listen)
            ))?;

        // tls.cert и tls.key — файлы должны существовать
        if !self.tls.cert.exists() {
            return Err(ConfigError::Validation(
                format!("tls.cert '{}' does not exist", self.tls.cert.display())
            ));
        }
        if !self.tls.key.exists() {
            return Err(ConfigError::Validation(
                format!("tls.key '{}' does not exist", self.tls.key.display())
            ));
        }

        // users — минимум один
        if self.users.is_empty() {
            return Err(ConfigError::Validation(
                "users list is empty — add at least one user".to_string()
            ));
        }

        // Каждый пользователь
        let mut names = std::collections::HashSet::new();
        for user in &self.users {
            // Имя не пустое
            if user.name.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "user name cannot be empty".to_string()
                ));
            }

            // Имена уникальны
            if !names.insert(user.name.clone()) {
                return Err(ConfigError::Validation(
                    format!("duplicate user name '{}'", user.name)
                ));
            }

            // Пароль ровно 64 символа
            if user.password.len() != 64 {
                return Err(ConfigError::Validation(format!(
                    "user '{}': password must be exactly 64 characters, got {}",
                    user.name,
                    user.password.len()
                )));
            }

            // Пароль только из печатаемых ASCII символов (без пробелов)
            if !user.password.chars().all(|c| c.is_ascii_graphic()) {
                return Err(ConfigError::Validation(format!(
                    "user '{}': password must contain only printable ASCII characters (no spaces)",
                    user.name
                )));
            }
        }

        // log.level — известное значение
        match self.log.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => return Err(ConfigError::Validation(
                format!("log.level '{}' is invalid, use: trace/debug/info/warn/error", other)
            )),
        }

        Ok(())
    }

    /// Возвращает пользователя по паролю, или None если не найден.
    pub fn find_user_by_password(&self, password: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| u.password == password)
    }

    /// Возвращает пользователя по имени.
    pub fn find_user_by_name(&self, name: &str) -> Option<&UserConfig> {
        self.users.iter().find(|u| u.name == name)
    }

    /// Возвращает listen адрес как SocketAddr.
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.server.listen.parse().unwrap() // уже проверено в validate()
    }
}

// ============================================================================
// Генерация пароля
// ============================================================================

/// Генерирует криптографически случайный пароль из 64 hex символов.
/// Удобно для онбординга новых пользователей.
pub fn generate_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32]; // 32 bytes = 64 hex chars
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_password() -> String {
        "a".repeat(64)
    }

    fn minimal_yaml(cert_path: &str, key_path: &str) -> String {
        format!(r#"
server:
  listen: "0.0.0.0:4433"

tls:
  cert: "{}"
  key: "{}"

users:
  - name: "alice"
    password: "{}"
"#, cert_path, key_path, valid_password())
    }

    // Создаём временные фиктивные файлы для тестов
    fn temp_tls_files() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
        let cert = tempfile::NamedTempFile::new().unwrap();
        let key  = tempfile::NamedTempFile::new().unwrap();
        (cert, key)
    }

    #[test]
    fn test_minimal_config_parses() {
        let (cert, key) = temp_tls_files();
        let yaml = minimal_yaml(
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
        );
        let cfg = Config::from_str(&yaml).unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0:4433");
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].name, "alice");
    }

    #[test]
    fn test_defaults_applied() {
        let (cert, key) = temp_tls_files();
        let yaml = minimal_yaml(
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
        );
        let cfg = Config::from_str(&yaml).unwrap();
        assert_eq!(cfg.server.max_connections, 1024);
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.bandwidth.up_mbps, 0);
        assert_eq!(cfg.bandwidth.down_mbps, 0);
        assert!(cfg.log.file.is_none());
    }

    #[test]
    fn test_password_too_short() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "tooshort"
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap());

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("64 characters"));
    }

    #[test]
    fn test_password_too_long() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "{}"
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap(), "a".repeat(65));

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("64 characters"));
    }

    #[test]
    fn test_duplicate_user_names() {
        let (cert, key) = temp_tls_files();
        let pw = valid_password();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "{}"
  - name: "alice"
    password: "{}"
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap(), pw, "b".repeat(64));

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate user name"));
    }

    #[test]
    fn test_empty_users() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
tls:
  cert: "{}"
  key: "{}"
users: []
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap());

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_invalid_log_level() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "{}"
log:
  level: "verbose"
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap(), valid_password());

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("log.level"));
    }

    #[test]
    fn test_invalid_listen_addr() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "not-an-address"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "{}"
"#, cert.path().to_str().unwrap(), key.path().to_str().unwrap(), valid_password());

        let err = Config::from_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("server.listen"));
    }

    #[test]
    fn test_multiple_users() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "127.0.0.1:4433"
tls:
  cert: "{}"
  key: "{}"
users:
  - name: "alice"
    password: "{}"
  - name: "bob"
    password: "{}"
  - name: "charlie"
    password: "{}"
"#,
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );

        let cfg = Config::from_str(&yaml).unwrap();
        assert_eq!(cfg.users.len(), 3);
        assert!(cfg.find_user_by_name("bob").is_some());
        assert!(cfg.find_user_by_password(&"c".repeat(64)).is_some());
    }

    #[test]
    fn test_full_config() {
        let (cert, key) = temp_tls_files();
        let yaml = format!(r#"
server:
  listen: "0.0.0.0:4433"
  max_connections: 500

tls:
  cert: "{}"
  key: "{}"

bandwidth:
  up_mbps: 1000
  down_mbps: 2000

users:
  - name: "alice"
    password: "{}"

log:
  level: "debug"
  file: "/var/log/flux.log"
"#,
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
            valid_password(),
        );

        let cfg = Config::from_str(&yaml).unwrap();
        assert_eq!(cfg.server.max_connections, 500);
        assert_eq!(cfg.bandwidth.up_mbps, 1000);
        assert_eq!(cfg.bandwidth.down_mbps, 2000);
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.file, Some(PathBuf::from("/var/log/flux.log")));
    }

    #[test]
    fn test_generate_password_length() {
        let pw = generate_password();
        assert_eq!(pw.len(), 64);
        assert!(pw.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_password_unique() {
        let pw1 = generate_password();
        let pw2 = generate_password();
        assert_ne!(pw1, pw2, "Два пароля не должны совпадать");
    }
}
