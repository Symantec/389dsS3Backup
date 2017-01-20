package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ShowMax/go-fqdn"
	_ "github.com/Symantec/tricorder/go/tricorder"
	"github.com/howeyc/gopass"
	"github.com/kr/s3/s3util"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ldap.v2"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	//"net"
	"net/http"
	"net/rpc"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type BackupConfig struct {
	Bind_dn               string
	Bind_passwd           string
	S3url                 string
	Aws_access_key_id     string
	Aws_secret_access_key string
	Http_proxy            string
	//Backup_directory      string
	//Restore_directory     string
	//monitor_addr          string
}
type BackupConfigFile struct {
	Backup BackupConfig
}

var (
	Version          = "No version provided"
	app              = kingpin.New("backup_ldap ", "A command-line 389 ds backup/restore utility to s3.")
	vers             = app.Version(Version)
	debug            = app.Flag("debug", "Enable debug mode.").Bool()
	addr             = app.Flag("addr", "Address ").Default(":11100").String()
	s3url            = app.Flag("s3url", "URL for the s3 backup file (ex: https://$YOURBUCKET.s3.amazonaws.com/backup.tar.enc)").String()
	backupDirectory  = app.Flag("backupDirectory", "directory for 389 backup dump").Default("/export/auto-backup/").String()
	restoreDirectory = app.Flag("restoreDirectory", "directory for 389 archive restore").Default("/export/auto-restore/").String()
	configFilename   = app.Flag("config", "Configuration Filename").Default("./backup_config.yml").String()
	extraBackupFile  = app.Flag("extrafile", "Extra File to Backup").String()

	runtest = app.Command("runtest", "Run full end to end backup_restore")

	singleBackup = app.Command("singleBackup", "perform a single backup")

	runRestore = app.Command("restore", "Run a single restore from s3 into the current localhost")

	runBackupDaemon = app.Command("backupDaemon", "Run continuous backup attempts in the background")
	attemptInterval = runBackupDaemon.Arg("interval", "interval between regular backup attempts").Default("60s").Duration()

	backupAttemptCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ldap_backup_attempt_count",
			Help: "LDAP backup attempts.",
		},
		[]string{"host"},
	)
	backupSuccessCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ldap_backup_success_count",
			Help: "LDAP backup success counter.",
		},
		[]string{"host"},
	)
)

func generateBackup(server string, bindDN string, bindPassword string, targetDir string) (string, error) {
	return doLDAPTask(server, bindDN, bindPassword, targetDir, "cn=example backup,cn=backup,cn=tasks,cn=config")
}

func restoreFromBackup(server string, bindDN string, bindPassword string, targetDir string) (string, error) {
	return doLDAPTask(server, bindDN, bindPassword, targetDir, "cn=example backup,cn=restore,cn=tasks,cn=config")
}
func doLDAPTask(server string, bindDN string, bindPassword string, archiveDir string, taskDN string) (string, error) {
	hostnamePort := server + ":636"
	if *debug {
		log.Println("about to connect to:" + hostnamePort)
	}
	start := time.Now()
	conn, err := ldap.DialTLS("tcp", hostnamePort, &tls.Config{ServerName: server})
	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connction failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return "", err
	}
	endConnection := time.Since(start).Seconds() * 1000
	defer conn.Close()
	if *debug {
		log.Printf("connectionDelay = %v connecting to: %v:", endConnection, hostnamePort)
	}

	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		log.Printf("bind failurei (%s)", err.Error())
		return "", err
	}

	//   dn: cn=example backup,cn=backup,cn=tasks,cn=config
	//   objectclass: extensibleObject
	//   cn: example backup
	//   nsArchiveDir: /export/backups/
	//   nsDatabaseType: ldbm database
	///const backupTaskDN = "cn=example backup,cn=backup,cn=tasks,cn=config"
	//const targetDir = "/export/backup"
	addRequest := ldap.NewAddRequest(taskDN)
	addRequest.Attribute("objectclass", []string{"extensibleObject"})
	addRequest.Attribute("cn", []string{"example backup"})
	addRequest.Attribute("nsArchiveDir", []string{archiveDir})
	addRequest.Attribute("nsDatabaseType", []string{"ldbm database"})
	addRequest.Attribute("ttl", []string{"10"})

	conn.Add(addRequest)
	if err != nil {
		log.Printf("modify failure failurei (%s)", err.Error())
		return "", err
	}

	//check for task complete
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		searchRequest := ldap.NewSearchRequest(
			taskDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=top)",
			[]string{"cn", "nstasklog", "nstaskstatus", "nstaskexitcode"},
			nil,
		)
		sr, err := conn.Search(searchRequest)
		if err != nil {
			log.Printf("search failure (%s)", err.Error())
			return "", err
		}
		if *debug {
			log.Printf("%+v\n", sr)
		}
		entry := sr.Entries[0]
		taskStatus := entry.GetAttributeValue("nstaskstatus")
		if *debug {
			log.Printf("status=%s\n", taskStatus)
		}
		exitCode := entry.GetAttributeValue("nstaskexitcode")
		switch exitCode {
		case "0":
			if *debug {
				log.Printf("success\n")
			}
			return archiveDir, nil
		case "":
			if *debug {
				log.Printf("not done yet\n")
			}
			continue
		}
		// error
		taskLog := entry.GetAttributeValue("nstasklog")
		log.Printf("Failure: log=%s\n", taskLog)
		err = errors.New("Failure to complete")
		return "", err

		/*
		   objectClass: extensibleObject
		   objectClass: top
		   cn: example backup
		   nsarchivedir: /export/backups/
		   nsdatabasetype: ldbm database
		   ttl: 30
		   nstaskcurrentitem: 0
		   nstasktotalitems: 1
		   nstasklog:: QmVnaW5uaW5nIGJhY2t1cCBvZiAnbGRibSBkYXRhYmFzZScKL2V4cG9ydC9iYWNrdX
		    .
		    .
		    .
		    BzIGV4aXN0cy4gUmVuYW1pbmcgdG8gL2V4cG9ydC9iYWNrdXBzLmJhawpCYWNraW5nIHVwIGZpbGU
		    oL2V4cG9ydC9iYWNrdXBzL0RCVkVSU0lPTikKQmFja3VwIGZpbmlzaGVkLg==
		   nstaskstatus: Backup finished.
		   nstaskexitcode: 0
		*/

	}
	err = errors.New("Task Incomplete or never Found")
	log.Printf("task Failure (%s)", err.Error())
	return "", err
}

// Next section copied from : http://blog.ralch.com/tutorial/golang-working-with-tar-and-gzip/
// https://gist.github.com/svett/dc27b7fb04c2549e3ada

func tarit(source, target string) error {
	//filename := filepath.Base(source)
	//target = filepath.Join(target, fmt.Sprintf("%s.tar", filename))
	tarfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer tarfile.Close()

	tarball := tar.NewWriter(tarfile)
	defer tarball.Close()
	/*
		info, err := os.Stat(source)
		if err != nil {
			return nil
		}
	*/
	var baseDir string
	//if info.IsDir() {
	//	baseDir = filepath.Base(source)
	//}

	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if err := tarball.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tarball, file)
		return err
	})
}

func untar(tarball, target string) error {
	reader, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(file, tarReader)
		if err != nil {
			return err
		}
	}
	return nil
}

// end of copy

func encrypt(source, target, passwd string) error {
	//openssl enc -e -pass stdin -in backup.ldif -out foo.bar -a
	cmd := exec.Command("openssl", "enc", "-e", "-aes-256-cbc", "-pass", "stdin", "-in", source, "-out", target, "-a")
	cmd.Stdin = strings.NewReader(passwd)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
		return err
	}
	if *debug {
		log.Printf("in all caps: %q source=%s target=%s\n", out.String(), source, target)
	}
	return nil
}

func decrypt(source, target, passwd string) error {
	//openssl enc -d -pass stdin -in foo.bar -a -out restored
	//openssl enc -e -pass stdin -in backup.ldif -out foo.bar -a
	if *debug {
		log.Printf("start decrypt source=%s target=%s\n", source, target)
	}
	cmd := exec.Command("openssl", "enc", "-d", "-aes-256-cbc", "-pass", "stdin", "-in", source, "-out", target, "-a")
	cmd.Stdin = strings.NewReader(passwd)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("decryption failure")
		log.Fatal(err)
		return err
	}
	if *debug {
		log.Printf("decrypt in all caps: %q source=%s target=%s\n", out.String(), source, target)
	}
	return nil
}

//Given a source location(directory) returns an encrypted tarball of the same directory
func tarAndEncryptBackup(source, target, passphrase string) error {
	if *extraBackupFile != "" {
		//err := os.Link(*extraBackupFile, dst)
		in, err := os.Open(*extraBackupFile)
		if err != nil {
			return err
		}
		defer in.Close()

		dst := fmt.Sprintf("%s/extra", source)
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()

		if _, err = io.Copy(out, in); err != nil {
			return err
		}

		err = out.Sync()
		if err != nil {
			return err
		}

	}
	var intermediateTarget string
	intermediateTarget = fmt.Sprintf("%s.encint", target)

	err := tarit(source, intermediateTarget)
	if err != nil {
		return err
	}
	err = encrypt(intermediateTarget, target, passphrase)
	if err != nil {
		return err
	}
	err = os.Remove(intermediateTarget)
	return err
}

func DecryptUntarFile(source, target, passphrase string) error {
	var intermediateSource string
	intermediateSource = fmt.Sprintf("%s.decint", source)
	err := decrypt(source, intermediateSource, passphrase)
	if err != nil {
		return err
	}
	err = untar(intermediateSource, target)
	if err != nil {
		return err
	}
	err = os.Remove(intermediateSource)
	return err
}

// section original from https://gist.github.com/howeyc/5021940

func open(s string) (io.ReadCloser, error) {
	if isURL(s) {
		return s3util.Open(s, nil)
	}
	return os.Open(s)
}

func create(s string) (io.WriteCloser, error) {
	if isURL(s) {
		header := make(http.Header)
		header.Add("x-amz-acl", "public-read")
		return s3util.Create(s, header, nil)
	}
	return os.Create(s)
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func s3cp(awsKeyID, awsSecretAccessKey, source, dest string) error {
	s3util.DefaultConfig.AccessKey = awsKeyID
	s3util.DefaultConfig.SecretKey = awsSecretAccessKey

	r, err := open(source)
	if err != nil {
		log.Print(err)
		return err
	}

	w, err := create(dest)
	if err != nil {
		log.Print(err)
		return err
	}

	_, err = io.Copy(w, r)
	if err != nil {
		log.Fatal(err)
		return err
	}

	err = w.Close()
	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}

// end of copy

//copy from http://stackoverflow.com/questions/33450980/golang-remove-all-contents-of-a-directory
func removeDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

// end of copy

func getRandomPassphrase() (string, error) {
	// in memory of https://xkcd.com/221/ ......
	//return "9", nil
	const numBytes = 32
	localRand := make([]byte, numBytes)
	_, err := rand.Read(localRand)
	if err != nil {
		//fmt.Println("error:", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(localRand), nil

}

func testAll(bindDN, bindPassword, s3url, awsKeyID, awsSecretAccessKey string) {

	const archiveDir = "/export/backup"
	const targetTar = "/tmp/target1.tar.enc"

	passphrase, err := getRandomPassphrase()
	if err != nil {
		log.Printf("error on random passphrase (%s)", err.Error())
		panic("cannot get random")
	}
	//const s3bucketUrl = "https://global-s3-cpe-dev-ldapbackup.s3.amazonaws.com/foo.tar"

	err = doSingleBackup(bindDN, bindPassword, archiveDir, passphrase, s3url, awsKeyID, awsSecretAccessKey)
	if err != nil {
		log.Printf("error on making backup (%s)", err.Error())
		panic("cannot get random")
	}

	log.Printf("upload complete/starting restoore\n")

	const testTarget = "/tmp/backuptest"
	err = doRestore(bindDN, bindPassword, testTarget, passphrase, s3url, awsKeyID, awsSecretAccessKey)

	if err != nil {
		log.Printf("error on restoring backup (%s)", err.Error())
		panic("cannot restore")
	}
	err = removeDirectory(testTarget)
	if err != nil {
		log.Printf("error renoving directoru (%s)", err.Error())
		panic("cleanup failure")
	}
}

func doSingleBackup(bindDN, bindPassword, exportDirectory, passphrase, s3url, awsKeyID, awsSecretAccessKey string) error {
	archiveDir := exportDirectory
	hostname := fqdn.Get()

	if *debug {
		log.Printf("starting do Single backup\n")
	}
	backupAttemptCounter.WithLabelValues(hostname).Add(1)

	_, err := generateBackup(hostname, bindDN, bindPassword, archiveDir)
	if err != nil {
		return err
	}

	// Yes there is a race condition here
	randomID, err := getRandomPassphrase()
	if err != nil {
		log.Printf("error on random passphrase (%s)", err.Error())
		return err
	}
	hexID := hex.EncodeToString([]byte(randomID))
	targetTar := "/tmp/target1-" + hexID[:10] + ".tar.enc"

	err = tarAndEncryptBackup(archiveDir, targetTar, passphrase)
	if err != nil {
		log.Printf("tar failure (%s)", err.Error())
		return err
	}
	defer os.Remove(targetTar)

	err = s3cp(awsKeyID, awsSecretAccessKey, targetTar, s3url)
	if err != nil {
		if *debug {
			log.Printf("s3 upload failure key=%s sec=%s (%s)", awsKeyID, awsSecretAccessKey, err.Error())
		}
		log.Printf("s3 upload fail %s\n", err.Error())
		return err
	}
	backupSuccessCounter.WithLabelValues(hostname).Add(1)
	return nil
}

func doRestore(bindDN, bindPassword, restoreDirectory, passphrase, s3url, awsKeyID, awsSecretAccessKey string) error {

	tmpfile, err := ioutil.TempFile("/tmp", "s3download")
	if err != nil {
		log.Printf("cannot create tempfile %s", err.Error())
		return err
	}
	s3dest := tmpfile.Name()
	defer os.Remove(s3dest)

	err = s3cp(awsKeyID, awsSecretAccessKey, s3url, s3dest)
	if err != nil {
		log.Printf("s3 upload failure key=%s sec=%s (%s)", awsKeyID, awsSecretAccessKey, err.Error())
		panic("cannot upload to s3")
	}
	err = DecryptUntarFile(s3dest, restoreDirectory, passphrase)
	if err != nil {
		log.Printf("cannot untar/decrypt (%s)", err.Error())
		return err
	}

	hostname := fqdn.Get()
	_, err = restoreFromBackup(hostname, bindDN, bindPassword, restoreDirectory)
	if err != nil {
		log.Printf("Cannot restore (%s)", err.Error())
		return err
	}

	return nil
}

/// Panics OR returns a password in string format
func getDomainPassword(uiName string) string {
	fmt.Printf("Password for %s: ", uiName)

	// Silent. For printing *'s use gopass.GetPasswdMasked()
	pass, err := gopass.GetPasswd()
	if err != nil {
		// Handle gopass.ErrInterrupted or getch() read error
		panic("no password")
	}
	return string(pass[:])
}

func getDerivedPassphraseString(password string) string {
	salt := " https://xkcd.com/221/"
	passphrase := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha512.New)
	return base64.StdEncoding.EncodeToString(passphrase)
}

func backupDaemon(bindDN, bindPassword, backupDirectory, passphrase, s3url, awsKeyID, awsSecretAccessKey string) error {

	log.Printf("starting preflight tests\n")
	// I do an initial... flight test to check basic parameters...
	// if it is AN ldap error... probably we need to panic as there is no recovery
	err := doSingleBackup(bindDN, bindPassword, backupDirectory, passphrase, s3url, awsKeyID, awsSecretAccessKey)
	if err != nil {
		log.Printf("backup failed %s", err.Error())
		switch i := err.(type) {
		case *ldap.Error:
			if i.ResultCode == ldap.LDAPResultInvalidCredentials {
				panic("invalid credentials")
			}
		}
		log.Printf("Preflight Checks with issues will continue... but backups might fail\n")
	} else {
		log.Printf("Preflight Checks sufficiently syccessful\n")
	}
	const retrySecs = 10
	time.Sleep(time.Duration(retrySecs) * time.Second)

	//start background work...
	go func() {
		const maxRetries = 4
		for {
			start := time.Now()
			log.Printf("Starting S3 Backup")
			for i := 0; i < maxRetries; i++ {
				err := doSingleBackup(bindDN, bindPassword, backupDirectory, passphrase, s3url, awsKeyID, awsSecretAccessKey)
				if err != nil {
					log.Printf("backup attempt failed %s", err.Error())

					time.Sleep(time.Duration(retrySecs) * time.Second)
					continue
				}
				log.Printf("successful Backup to S3")
				break //successful backup
			}
			runtime := time.Since(start)
			time.Sleep(*attemptInterval - runtime)
		}
	}()

	//start monitoring handlers
	rpc.HandleHTTP()
	http.Handle("/metricsP", prometheus.Handler())
	err = http.ListenAndServe(":11100", nil)
	return err
}

func init() {
	prometheus.MustRegister(backupAttemptCounter)
	prometheus.MustRegister(backupSuccessCounter)
}

func main() {

	parsedArgs := kingpin.MustParse(app.Parse(os.Args[1:]))
	if _, err := os.Stat(*configFilename); os.IsNotExist(err) {
		log.Printf("Missing config file: %s\n", *configFilename)
		os.Exit(1)
	}

	var config BackupConfigFile
	source, err := ioutil.ReadFile(*configFilename)
	if err != nil {
		log.Printf("Cannot read config file: %s. Err=%s\n", *configFilename, err.Error())
		os.Exit(1)
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		log.Printf("Cannot parse config file: %s. Err=%s\n", *configFilename, err.Error())
		os.Exit(1)
	}
	//if *debug {
	//	log.Printf("%+v", config.Backup)
	//}

	// we prefer the command line over the config
	if config.Backup.S3url != "" && *s3url == "" {
		*s3url = config.Backup.S3url
	}

	if *s3url == "" {
		log.Printf("Cannot proceed with emtpy s3 url")
		os.Exit(1)
	}

	_, err = url.Parse(*s3url)
	if err != nil {
		log.Printf("Cannot parse s3 url")
		os.Exit(1)
	}
	// todo ... more validation on s3 url.. EX: is https
	if *debug {
		log.Printf("url='%s'", *s3url)
	}

	// For the aws config: prefer env over config
	awsKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	if awsKeyID == "" {
		awsKeyID = config.Backup.Aws_access_key_id
	}
	if awsKeyID == "" {
		log.Printf("Cannot proceed with emtpy AWS Key ID ")
		os.Exit(1)
	}

	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsSecretAccessKey == "" {
		awsSecretAccessKey = config.Backup.Aws_secret_access_key
	}
	if awsSecretAccessKey == "" {
		log.Printf("Cannot proceed with emtpy secret access Key ")
		os.Exit(1)
	}

	//proxy override from config when not also set in the env
	if config.Backup.Http_proxy != "" && os.Getenv("HTTP_PROXY") == "" {
		if *debug {
			log.Printf("setting http proxy to: '%s'", config.Backup.Http_proxy)
		}
		proxyUrl, err := url.Parse(config.Backup.Http_proxy)
		if err != nil {
			log.Printf("Cannot parse config http_proxy aborting\n")
			os.Exit(1)
		}
		http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
	}

	bindDN := "cn=directory manager"
	if config.Backup.Bind_dn != "" {
		bindDN = config.Backup.Bind_dn
	}
	//Last we check the password
	bindPassword := config.Backup.Bind_passwd
	if bindPassword == "" {
		bindPassword = getDomainPassword(bindDN)
	}

	// common setup
	ldap.DefaultTimeout = 4 * time.Second

	switch parsedArgs {
	case runtest.FullCommand():
		testAll(bindDN, bindPassword, *s3url, awsKeyID, awsSecretAccessKey)
		os.Exit(0)
	case singleBackup.FullCommand():
		passphrase := getDerivedPassphraseString(bindPassword)
		err := doSingleBackup(bindDN, bindPassword, *backupDirectory, passphrase, *s3url, awsKeyID, awsSecretAccessKey)
		if err != nil {
			log.Printf("backup failed: %s", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	case runRestore.FullCommand():
		passphrase := getDerivedPassphraseString(bindPassword)
		err := doRestore(bindDN, bindPassword, *restoreDirectory, passphrase, *s3url, awsKeyID, awsSecretAccessKey)
		if err != nil {
			log.Printf("restore failed: %s", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	case runBackupDaemon.FullCommand():
		passphrase := getDerivedPassphraseString(bindPassword)
		backupDaemon(bindDN, bindPassword, *restoreDirectory, passphrase, *s3url, awsKeyID, awsSecretAccessKey)
		os.Exit(1)

	}
}
