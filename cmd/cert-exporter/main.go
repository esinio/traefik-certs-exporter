package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/fsnotify/fsnotify"

	"git.esin.io/lab/traefik-certs-exporter/repo"
)

const (
	PemNamePrivKey   = "privkey.pem"
	PemNameChain     = "chain.pem"
	PemNameFullchain = "fullchain.pem"
	PemNameCert      = "cert.pem" //
)

var (
	acmeFile       string
	pemStoredDir   string
	dockerLabelKey string
)

var (
	log       *slog.Logger
	logDebug  bool
	logSource bool
)

func init() {
	flag.BoolVar(&logDebug, "log.debug", false, "bool value of debug")
	flag.BoolVar(&logSource, "log.source", false, "bool value of log source file")
	flag.StringVar(&acmeFile, "f", "./acme.json", "acme.json file path")
	flag.StringVar(&pemStoredDir, "d", "./certs", "certs stored directory")
	flag.StringVar(&dockerLabelKey, "l", "traefik.cert.domain", "the key of the docker container label")
}

func main() {
	if ok := flag.Parsed(); !ok {
		flag.Parse()
	}

	log = useTextLogger()
	log.Info("start to run file watcher")
	log.Info("flag parsed")

	if err := run(); err != nil {
		log.Error(err.Error())
	}
}

func useTextLogger() *slog.Logger {
	logLevel := slog.LevelInfo
	if ok := logDebug; ok {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   logSource,
			Level:       logLevel,
			ReplaceAttr: nil,
		}),
	)
	slog.SetDefault(logger)
	return logger
}

func run() error {
	if err := DumpCerts(); err != nil {
		return err
	}

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create new watcher: %w", err)
	}
	defer watcher.Close()

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					fmt.Errorf("failed to receive watcher events: %w", err)
				}
				// log.Printf("got new watcher event: %s", event)
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Chmod) {
					// do something else
					log.Info("received fs event", "event", event)
					if err := DumpCerts(); err != nil {
						log.Error(err.Error())
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					fmt.Errorf("failed to receive watcher error: %w", err)
				}
				errWrap := fmt.Errorf("watcher error on select: %w", err)
				log.Error(errWrap.Error())
			}
		}
	}()

	// Add a path.
	if err := watcher.Add(acmeFile); err != nil {
		return fmt.Errorf("failed to add target to watcher: %w", err)
	}

	<-make(chan struct{})

	return nil
}

func DumpCerts() error {
	log.Info("start to dump certs from acme.json file")
	resolvers, err := ReadJSONFile(acmeFile)
	if err != nil {
		return err
	}

	for resolver, provider := range *resolvers {
		log.Info("found cert resolvers", "name", resolver, "email", provider.Account.Email, "status", provider.Account.Registration.Body.Status)

		// loop encryption
		for _, cert := range provider.Certificates {
			if err := DumpDomainCerts(cert.Domain.Main, cert.Key, cert.Certificate); err != nil {
				return err
			}
		}
	}
	return nil
}

func ReadJSONFile(f string) (*repo.Resolvers, error) {
	data, err := os.ReadFile(f)
	if err != nil {
		if ok := os.IsNotExist(err); ok {
			err = fmt.Errorf("file not exist: %w", err)
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	var resolvers repo.Resolvers
	err = json.Unmarshal(data, &resolvers)
	if err != nil {
		return nil, fmt.Errorf("failed to Unmarshal file: %w", err)
	}
	return &resolvers, nil
}

func DumpDomainCerts(domain string, encodedPriveKey, encodedCert string) error {
	pemFileDir := pemParentDir(pemStoredDir, domain) // parent directory.
	err := os.MkdirAll(pemFileDir, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to make domain directory: %w", err)
	}

	privkey, err := DecodeString(encodedPriveKey)
	if err != nil {
		return err
	}
	if _, err := CompareAndOverWritePemFile(pemFileDir, PemNamePrivKey, privkey); err != nil {
		return err
	}

	pemfullChain, err := DecodeString(encodedCert)
	if err != nil {
		return err
	}
	pemfullChainModified, err := CompareAndOverWritePemFile(pemFileDir, PemNameFullchain, pemfullChain)
	if err != nil {
		return err
	}

	if ok := pemfullChainModified; ok {
		// shoud watch fullchain pem file
		if err := RestartDomainWatchedContainer(dockerLabelKey, domain); err != nil {
			return err
		}
	}

	pemCert, pemChain := DetachFullchainPem(string(pemfullChain))
	if _, err := CompareAndOverWritePemFile(pemFileDir, PemNameCert, []byte(pemCert)); err != nil {
		return err
	}

	if _, err := CompareAndOverWritePemFile(pemFileDir, PemNameChain, []byte(pemChain)); err != nil {
		return err
	}

	return nil
}

func DecodeString(v string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(v)
}

func DetachFullchainPem(fullChain string) (string, string) {
	idx := strings.Index(fullChain, "\n-----BEGIN CERTIFICATE-----")
	return fullChain[:idx], fullChain[idx+1:]
}

// a bool value returned means the write action had performed done or not
func CompareAndOverWritePemFile(fileDir, filename string, data []byte) (bool, error) {
	fp := pemFullPath(fileDir, filename)
	fd, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return false, fmt.Errorf("failed to open file when attempting to write: %w", err)
	}

	// read original file content
	originalData, err := io.ReadAll(fd)
	if err != nil {
		return false, fmt.Errorf("failed to read original pem file: %w", err)
	}

	// compare data with original file content
	if ok := reflect.DeepEqual(data, originalData); ok {
		// do nothing
		log.Info("pem file content as before, pass", "file", fp)
		return false, nil
	}

	// write data to file
	if _, err := fd.Write(data); err != nil {
		return false, fmt.Errorf("failed to write file: %w", err)
	}

	if err := fd.Sync(); err != nil {
		return false, fmt.Errorf("failed to commits the current contents of the file to stable storage: %w", err)
	}

	if err := fd.Close(); err != nil {
		return false, fmt.Errorf("failed to close file: %s, %w", fp, err)
	}

	return true, nil
}

func pemParentDir(storedDir, domain string) string {
	return filepath.Join(storedDir, domain)
}

func pemFullPath(parentDir, filename string) string {
	return filepath.Join(parentDir, filename)
}

func RestartDomainWatchedContainer(key, val string) error {
	l := fmt.Sprintf("%s=%s", key, val)
	return FindDockerContainersAndRestart(l)

}

func FindDockerContainersAndRestart(label string) error {
	apiClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to connect docker sock: %w", err)
	}
	defer apiClient.Close()

	ctx := context.Background()

	// downgrades the client's API version to match the APIVersion
	apiClient.NegotiateAPIVersion(ctx)

	opts := container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", label),
		),
	}
	containers, err := apiClient.ContainerList(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list docker containers: %w", err)
	}

	noWaitTimeout := 0
	for _, ctr := range containers {
		log.Info("found container:", "id", ctr.ID, "image", ctr.Image, "status", ctr.Status)

		err := apiClient.ContainerRestart(ctx, ctr.ID, container.StopOptions{
			Timeout: &noWaitTimeout,
		})
		if err != nil {
			log.Error("failed to restart docker container", "id", ctr.ID, "image", ctr.Image, "label", label, "error", err)
		}

	}

	return nil
}
