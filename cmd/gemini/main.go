package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"bytes" // 使用 bytes.Equal 替代 reflect.DeepEqual
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/fsnotify/fsnotify"

	// 假设 repo 包内容已移到本地，或使用内部结构体
	// "git.esin.io/lab/traefik-certs-exporter/repo" // 移除对私有库的硬依赖
)

const (
	PemNamePrivKey   = "privkey.pem"
	PemNameChain     = "chain.pem"
	PemNameFullchain = "fullchain.pem"
	PemNameCert      = "cert.pem"
)

// Config 结构体：集中管理所有命令行参数和配置
type Config struct {
	ACMEFile       string
	PEMStoredDir   string
	DockerLabelKey string
	LogDebug       bool
	LogSource      bool
}

// Exporter 结构体：封装应用状态、配置和外部依赖
type Exporter struct {
	Config *Config
	Logger *slog.Logger
	Docker *client.Client // 客户端只初始化一次
}

// ===================================================================
// 1. 初始化和配置
// ===================================================================

func (cfg *Config) ParseFlags() {
	flag.BoolVar(&cfg.LogDebug, "log.debug", false, "bool value of debug")
	flag.BoolVar(&cfg.LogSource, "log.source", false, "bool value of log source file")
	flag.StringVar(&cfg.ACMEFile, "f", "./acme.json", "acme.json file path")
	flag.StringVar(&cfg.PEMStoredDir, "d", "./certs", "certs stored directory")
	flag.StringVar(&cfg.DockerLabelKey, "l", "traefik.cert.domain", "the key of the docker container label")
	flag.Parse()
}

func useTextLogger(cfg *Config) *slog.Logger {
	logLevel := slog.LevelInfo
	if cfg.LogDebug {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: cfg.LogSource,
			Level:     logLevel,
		}),
	)
	slog.SetDefault(logger)
	return logger
}

func main() {
	cfg := &Config{}
	cfg.ParseFlags()

	logger := useTextLogger(cfg)
	logger.Info("start to run cert exporter", "acmeFile", cfg.ACMEFile, "certsDir", cfg.PEMStoredDir)

	// 仅初始化一次 Docker 客户端
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		logger.Error("failed to connect docker daemon", "error", err)
		os.Exit(1)
	}
	defer dockerClient.Close()

	// 版本协商
	dockerClient.NegotiateAPIVersion(context.Background())

	exporter := &Exporter{
		Config: cfg,
		Logger: logger,
		Docker: dockerClient,
	}

	if err := exporter.Run(); err != nil {
		exporter.Logger.Error("application exited with error", "error", err)
		os.Exit(1)
	}
}

// ===================================================================
// 2. 核心运行和文件监听
// ===================================================================

func (e *Exporter) Run() error {
	// 首次启动先运行一次
	if err := e.DumpAllCerts(); err != nil {
		e.Logger.Error("initial dump failed", "error", err)
		// 初始失败应返回错误，但这里可能只需要警告并继续监听
	}

	// 优化 1：监听文件所在的父目录，而不是文件本身
	acmeDir := filepath.Dir(e.Config.ACMEFile)
	acmeBase := filepath.Base(e.Config.ACMEFile)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create new watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(acmeDir); err != nil {
		return fmt.Errorf("failed to add target directory to watcher: %w", err)
	}
	e.Logger.Info("watching directory for acme file changes", "directory", acmeDir)

	// 用于去抖动 (Debouncing)
	const debounceDuration = 100 * time.Millisecond
	var lastEventTime time.Time

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("watcher events channel closed")
			}
			
			// 优化 2：精确匹配 Traefik 的原子重命名和写入
			// Traefik 的原子写入通常是：写入临时文件 -> RENAME 成 acme.json
			isTargetFile := filepath.Base(event.Name) == acmeBase
			
			// 优化 3：Debounce（去抖动）处理，防止短时间内多次触发
			if time.Since(lastEventTime) < debounceDuration {
				e.Logger.Debug("debounce: ignoring event", "event", event)
				continue
			}

			// 监听 RENAME 或 WRITE 事件
			if isTargetFile && (event.Has(fsnotify.Rename) || event.Has(fsnotify.Write)) {
				lastEventTime = time.Now()
				e.Logger.Info("received acme file change event, dumping certs...", "event", event.Op.String(), "file", event.Name)
				
				// 给 Traefik 足够时间完成写入和重命名
				time.Sleep(50 * time.Millisecond)

				if err := e.DumpAllCerts(); err != nil {
					e.Logger.Error("dump certs failed after file event", "error", err)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				// 致命错误，退出循环
				return fmt.Errorf("watcher errors channel closed")
			}
			// 非致命错误，记录并继续
			e.Logger.Error("watcher received error", "error", err)

		case <-context.Background().Done():
			return context.Background().Err()
		}
	}
}

// ===================================================================
// 3. 证书处理逻辑
// ===================================================================

// 使用内部结构体替代对外部私有 repo 包的依赖
type Certificate struct {
	Domain struct { Main string `json:"main"` } `json:"domain"`
	Key string `json:"key"`
	Certificate string `json:"certificate"`
}
type Account struct {
	Email string `json:"EmailAddress"`
	Registration struct { Body struct { Status string `json:"status"` } `json:"body"` } `json:"Registration"`
}
type Provider struct {
	Account Account `json:"Account"`
	Certificates []Certificate `json:"Certificates"`
}
type Resolvers map[string]Provider // top-level map

// DumpAllCerts 负责读取文件和循环处理
func (e *Exporter) DumpAllCerts() error {
	e.Logger.Info("start to dump certs from acme.json file")
	
	resolvers, err := e.ReadJSONFile()
	if err != nil {
		return err // 文件读取失败是致命错误
	}

	// 优化：使用一个计数器来判断是否有任何域处理成功
	successCount := 0
	
	for resolverName, provider := range resolvers {
		e.Logger.Info("found cert resolvers", "name", resolverName, "email", provider.Account.Email, "status", provider.Account.Registration.Body.Status)

		for _, cert := range provider.Certificates {
			domain := cert.Domain.Main
			
			// 优化：处理一个域失败，只记录错误，继续下一个
			if err := e.DumpDomainCerts(domain, cert.Key, cert.Certificate); err != nil {
				e.Logger.Error("failed to dump cert for domain", "domain", domain, "error", err)
				continue // 继续处理下一个证书
			}
			successCount++
		}
	}
	
	e.Logger.Info("cert dumping complete", "successful_certs", successCount)
	return nil
}

func (e *Exporter) ReadJSONFile() (Resolvers, error) {
	data, err := os.ReadFile(e.Config.ACMEFile)
	if err != nil {
		// 优化：更清晰的错误类型判断
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("acme file not exist: %s: %w", e.Config.ACMEFile, err)
		}
		return nil, fmt.Errorf("failed to read acme file: %s: %w", e.Config.ACMEFile, err)
	}

	var resolvers Resolvers
	if err := json.Unmarshal(data, &resolvers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal acme file: %w", err)
	}
	return resolvers, nil
}

func (e *Exporter) DumpDomainCerts(domain string, encodedPriveKey, encodedCert string) error {
	pemFileDir := filepath.Join(e.Config.PEMStoredDir, domain)
	
	// 确保目录存在
	if err := os.MkdirAll(pemFileDir, 0755); err != nil {
		return fmt.Errorf("failed to make domain directory %s: %w", pemFileDir, err)
	}

	// 1. 导出私钥 (privkey.pem)
	privkeyData, err := base64.StdEncoding.DecodeString(encodedPriveKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key for %s: %w", domain, err)
	}
	if _, err := e.CompareAndAtomicWritePem(pemFileDir, PemNamePrivKey, privkeyData, domain); err != nil {
		return err
	}

	// 2. 导出完整链 (fullchain.pem)
	fullChainData, err := base64.StdEncoding.DecodeString(encodedCert)
	if err != nil {
		return fmt.Errorf("failed to decode fullchain cert for %s: %w", domain, err)
	}
	
	// 关键：检查 fullchain 是否有修改
	modified, err := e.CompareAndAtomicWritePem(pemFileDir, PemNameFullchain, fullChainData, domain)
	if err != nil {
		return err
	}
	
	// 3. 导出证书和链 (cert.pem, chain.pem)
	pemCert, pemChain, err := DetachFullchainPem(string(fullChainData))
	if err != nil {
		return fmt.Errorf("failed to detach cert/chain for %s: %w", domain, err)
	}
	if _, err := e.CompareAndAtomicWritePem(pemFileDir, PemNameCert, []byte(pemCert), domain); err != nil {
		return err
	}
	if _, err := e.CompareAndAtomicWritePem(pemFileDir, PemNameChain, []byte(pemChain), domain); err != nil {
		return err
	}

	// 4. 重启容器
	if modified {
		e.Logger.Info("fullchain was modified, restarting watched container", "domain", domain)
		if err := e.RestartDomainWatchedContainer(domain); err != nil {
			// 记录错误，但不返回，因为证书文件已经更新成功
			e.Logger.Error("failed to restart docker container", "domain", domain, "error", err)
		}
	}

	return nil
}

// DetachFullchainPem 将 FullChain 分离为 Cert 和 Chain
func DetachFullchainPem(fullChain string) (string, string, error) {
	// 优化：确保 BEGIN CERTIFICATE 存在
	idx := strings.Index(fullChain, "\n-----BEGIN CERTIFICATE-----")
	if idx == -1 {
		// 可能是单个证书，没有 chain
		// 更好的做法是依赖于 Go 的 x509 库来解析，这里暂时保留原逻辑，但添加检查
		if strings.HasPrefix(fullChain, "-----BEGIN CERTIFICATE-----") {
			return fullChain, "", nil // 只有一个证书
		}
		return "", "", fmt.Errorf("invalid fullchain format: cannot find chain separator")
	}
	return fullChain[:idx], fullChain[idx+1:], nil
}

// 优化：重命名原函数，实现原子写入，并使用 bytes.Equal 提速
func (e *Exporter) CompareAndAtomicWritePem(fileDir, filename string, data []byte, domain string) (bool, error) {
	fp := filepath.Join(fileDir, filename)
	
	// 1. 尝试读取原始内容进行比较
	originalData, err := os.ReadFile(fp)
	if err == nil {
		// 优化：使用 bytes.Equal 提速
		if bytes.Equal(data, originalData) {
			e.Logger.Debug("pem file content as before, pass", "file", fp, "domain", domain)
			return false, nil // 内容相同，不写入
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to read existing file %s: %w", fp, err)
	}

	// 2. 内容不同或文件不存在，执行原子写入
	tmpFp := fp + ".tmp"
	if err := os.WriteFile(tmpFp, data, 0644); err != nil {
		return false, fmt.Errorf("failed to write temporary file %s: %w", tmpFp, err)
	}

	// 3. 原子重命名，覆盖原文件
	if err := os.Rename(tmpFp, fp); err != nil {
		return false, fmt.Errorf("failed to atomically rename temp file %s to %s: %w", tmpFp, fp, err)
	}
	
	e.Logger.Info("pem file content updated successfully", "file", fp, "domain", domain)
	return true, nil
}

// ===================================================================
// 4. Docker 交互
// ===================================================================

func (e *Exporter) RestartDomainWatchedContainer(domain string) error {
	label := fmt.Sprintf("%s=%s", e.Config.DockerLabelKey, domain)
	return e.FindDockerContainersAndRestart(label)
}

func (e *Exporter) FindDockerContainersAndRestart(label string) error {
	ctx := context.Background()
	
	// Docker 客户端已在 main 中初始化并传入 Exporter
	apiClient := e.Docker 

	opts := container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", label),
		),
	}
	containers, err := apiClient.ContainerList(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list docker containers with label '%s': %w", label, err)
	}

	if len(containers) == 0 {
		e.Logger.Debug("no containers found with label", "label", label)
		return nil
	}

	// 优化：使用 noWaitTimeout 变量
	noWaitTimeout := 0
	stopOptions := container.StopOptions{Timeout: &noWaitTimeout} 
	
	for _, ctr := range containers {
		e.Logger.Info("found container to restart", "id", ctr.ID[:12], "image", ctr.Image, "status", ctr.Status, "label", label)

		if err := apiClient.ContainerRestart(ctx, ctr.ID, stopOptions); err != nil {
			// 优化：记录错误，并继续下一个容器
			e.Logger.Error("failed to restart docker container", "id", ctr.ID[:12], "image", ctr.Image, "label", label, "error", err)
			continue
		}
		e.Logger.Info("successfully restarted container", "id", ctr.ID[:12])
	}

	return nil
}