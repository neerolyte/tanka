package jsonnet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/fatih/color"
	jsonnet "github.com/google/go-jsonnet"
	"github.com/pkg/errors"
	"google.golang.org/api/iterator"

	"github.com/grafana/tanka/pkg/jsonnet/jpath"
	"github.com/grafana/tanka/pkg/jsonnet/native"
)

var fileHashes sync.Map

var googleStorageLock sync.Once
var googleStorageClient *storage.Client
var googleStoragePaths map[string]bool

// Modifier allows to set optional parameters on the Jsonnet VM.
// See jsonnet.With* for this.
type Modifier func(vm *jsonnet.VM) error

// InjectedCode holds data that is "late-bound" into the VM
type InjectedCode map[string]string

// Set allows to set values on an InjectedCode, even when it is nil
func (i *InjectedCode) Set(key, value string) {
	if *i == nil {
		*i = make(InjectedCode)
	}

	(*i)[key] = value
}

// Opts are additional properties for the Jsonnet VM
type Opts struct {
	ExtCode     InjectedCode
	TLACode     InjectedCode
	ImportPaths []string
	EvalScript  string

	CachePath           string
	CacheEnvRegexes     []*regexp.Regexp
	WarnLongEvaluations time.Duration
}

// Clone returns a deep copy of Opts
func (o Opts) Clone() Opts {
	extCode, tlaCode := InjectedCode{}, InjectedCode{}

	for k, v := range o.ExtCode {
		extCode[k] = v
	}

	for k, v := range o.TLACode {
		tlaCode[k] = v
	}

	return Opts{
		TLACode:             tlaCode,
		ExtCode:             extCode,
		ImportPaths:         append([]string{}, o.ImportPaths...),
		EvalScript:          o.EvalScript,
		CachePath:           o.CachePath,
		CacheEnvRegexes:     o.CacheEnvRegexes,
		WarnLongEvaluations: o.WarnLongEvaluations,
	}
}

// MakeVM returns a Jsonnet VM with some extensions of Tanka, including:
// - extended importer
// - extCode and tlaCode applied
// - native functions registered
func MakeVM(opts Opts) *jsonnet.VM {
	vm := jsonnet.MakeVM()
	vm.Importer(NewExtendedImporter(opts.ImportPaths))

	for k, v := range opts.ExtCode {
		vm.ExtCode(k, v)
	}
	for k, v := range opts.TLACode {
		vm.TLACode(k, v)
	}

	for _, nf := range native.Funcs() {
		vm.NativeFunction(nf)
	}

	return vm
}

// EvaluateFile evaluates the Jsonnet code in the given file and returns the
// result in JSON form. It disregards opts.ImportPaths in favor of automatically
// resolving these according to the specified file.
func EvaluateFile(jsonnetFile string, opts Opts) (string, error) {
	bytes, _ := ioutil.ReadFile(jsonnetFile)
	return Evaluate(jsonnetFile, string(bytes), opts)

}

// Evaluate renders the given jsonnet into a string
func Evaluate(path, data string, opts Opts) (string, error) {
	ctx := context.Background()

	cache := opts.CachePath != ""
	if cache && len(opts.CacheEnvRegexes) > 0 {
		cache = false
		for _, regex := range opts.CacheEnvRegexes {
			cache = cache || regex.MatchString(path)
		}
	}

	// Create VM
	jpath, _, _, err := jpath.Resolve(path)
	if err != nil {
		return "", errors.Wrap(err, "resolving import paths")
	}
	opts.ImportPaths = jpath
	vm := MakeVM(opts)

	// Parse cache path and fetch from cache (if the item is there)
	var cacheItemPath, scheme string
	if cache {
		envHash, err := getEnvHash(vm, path, data)
		if err != nil {
			return "", err
		}

		parts := strings.Split(opts.CachePath, "://")
		cachePath := parts[1]

		switch scheme = parts[0]; scheme {
		case "file":
			cacheItemPath = filepath.Join(cachePath, envHash+".json")
			if _, err := os.Stat(cacheItemPath); err == nil {
				bytes, err := ioutil.ReadFile(cacheItemPath)
				return string(bytes), err
			} else if !os.IsNotExist(err) {
				return "", err
			}
		case "gs":
			parts := strings.SplitN(cachePath, "/", 2)
			bucketName, prefix := parts[0], parts[1]
			cacheItemPath = bucketName + "/" + strings.Trim(prefix, "/") + "/" + envHash + ".json"

			err = nil
			googleStorageLock.Do(func() {
				if googleStorageClient, err = storage.NewClient(ctx); err != nil {
					return
				}

				query := &storage.Query{Prefix: prefix}

				googleStoragePaths = map[string]bool{}
				bkt := googleStorageClient.Bucket(bucketName)
				it := bkt.Objects(ctx, query)
				for {
					var attrs *storage.ObjectAttrs
					attrs, err = it.Next()
					if err == iterator.Done {
						err = nil
						break
					}
					if err != nil {
						return
					}
					googleStoragePaths[attrs.Bucket+"/"+attrs.Name] = true
				}
				if err != nil {
					googleStorageClient = nil
				}
			})
			if googleStorageClient == nil {
				return "", err
			}

			if _, ok := googleStoragePaths[cacheItemPath]; ok {
				fmt.Println("Got " + cacheItemPath + " from cache")
				reader, err := googleStorageClient.Bucket(bucketName).Object(strings.SplitN(cacheItemPath, "/", 2)[1]).NewReader(ctx)
				if err != nil {
					return "", err
				}
				bytes, err := io.ReadAll(reader)
				return string(bytes), err
			}

			if err != nil {
				return "", err
			}

		default:
			return "", errors.New("invalid cache path scheme: " + scheme)
		}
	}

	startTime := time.Now()
	content, err := vm.EvaluateAnonymousSnippet(path, data)
	if err != nil {
		return "", err
	}
	if opts.WarnLongEvaluations != 0 {
		if evalTime := time.Since(startTime); evalTime > opts.WarnLongEvaluations {
			log.Println(color.YellowString("[WARN] %s took %fs to evaluate", path, evalTime.Seconds()))
		}
	}

	if cache {
		switch scheme {
		case "file":
			err = ioutil.WriteFile(cacheItemPath, []byte(content), 0644)
		case "gs":
			parts := strings.SplitN(cacheItemPath, "/", 2)
			bucketName, objectName := parts[0], parts[1]
			writer := googleStorageClient.Bucket(bucketName).Object(objectName).NewWriter(ctx)
			_, err = io.WriteString(writer, content)
			if err != nil {
				return "", err
			}
			err = writer.Close()
		}
	}

	return content, err
}

func getEnvHash(vm *jsonnet.VM, path, data string) (string, error) {
	node, _ := jsonnet.SnippetToAST(path, data)
	result := map[string]bool{}
	if err := importRecursive(result, vm, node, path); err != nil {
		return "", err
	}
	fileNames := []string{}
	for file := range result {
		fileNames = append(fileNames, file)
	}
	sort.Strings(fileNames)

	fullHasher := sha256.New()
	fullHasher.Write([]byte(data))
	for _, file := range fileNames {
		var fileHash []byte
		if got, ok := fileHashes.Load(file); ok {
			fileHash = got.([]byte)
		} else {
			bytes, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			hash := sha256.New()
			fileHash = hash.Sum(bytes)
			fileHashes.Store(file, fileHash)
		}
		fullHasher.Write(fileHash)
	}

	return base64.URLEncoding.EncodeToString(fullHasher.Sum(nil)), nil
}
