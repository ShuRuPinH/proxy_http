package main

import (
	"encoding/json"
	"os"
	"sync"
)

// Config хранит изменяемые во время работы настройки прокси.
// Доступ к полям сериализуется через RWMutex, чтобы можно было
// безопасно менять креды из админки во время обслуживания запросов.
type Config struct {
	mu        sync.RWMutex
	path      string
	ProxyUser string `json:"proxy_user"`
	ProxyPass string `json:"proxy_pass"`
}

// configFile описывает только сериализуемую часть конфига.
type configFile struct {
	ProxyUser string `json:"proxy_user"`
	ProxyPass string `json:"proxy_pass"`
}

// LoadConfig читает конфиг из файла. Если файла нет — создаёт его,
// используя переданные значения по умолчанию.
func LoadConfig(path, defaultUser, defaultPass string) (*Config, error) {
	c := &Config{
		path:      path,
		ProxyUser: defaultUser,
		ProxyPass: defaultPass,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Первый запуск: сохраняем дефолты на диск.
			return c, c.Save()
		}
		return nil, err
	}

	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	if cf.ProxyUser != "" {
		c.ProxyUser = cf.ProxyUser
	}
	if cf.ProxyPass != "" {
		c.ProxyPass = cf.ProxyPass
	}
	return c, nil
}

// Credentials возвращает текущие логин и пароль прокси.
func (c *Config) Credentials() (user, pass string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ProxyUser, c.ProxyPass
}

// SetCredentials обновляет логин и пароль в памяти.
func (c *Config) SetCredentials(user, pass string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ProxyUser = user
	c.ProxyPass = pass
}

// Save атомарно записывает текущий конфиг на диск.
func (c *Config) Save() error {
	c.mu.RLock()
	cf := configFile{ProxyUser: c.ProxyUser, ProxyPass: c.ProxyPass}
	path := c.path
	c.mu.RUnlock()

	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
