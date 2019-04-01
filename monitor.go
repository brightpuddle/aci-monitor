package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh/terminal"
)

const Version = "0.1.4"

var log *logrus.Logger
var Rev string

type Fabric struct {
	options   Args
	client    *http.Client
	startTime time.Time
}

func makeFabric() Fabric {
	args := getArgs()
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	httpClient := http.Client{
		Timeout: time.Second * 15,
		Jar:     cookieJar,
	}
	if args.Verbose {
		log.SetLevel(logrus.DebugLevel)
	}
	if args.JSON {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{ForceColors: true})
		log.SetOutput(colorable.NewColorableStdout())
	}
	return Fabric{
		options:   args,
		client:    &httpClient,
		startTime: time.Now(),
	}
}

type Args struct {
	IP       string `arg:"-i" help:"fabric IP address"`
	JSON     bool   `arg:"--json" help:"JSON logger, e.g. for splunk"`
	Password string `arg:"-p"`
	Snapshot string `arg:"-s" help:"Snapshot file"`
	Upgrade  bool   `arg:"--upgrade" help:"Monitor upgrade status"`
	Username string `arg:"-u"`
	Verbose  bool   `arg:"-v"`
}

type Fault struct {
	code     string
	descr    string
	dn       string
	json     gjson.Result
	severity string
}

func makeFault(json gjson.Result) Fault {
	return Fault{
		json:     json,
		dn:       json.Get("dn").Str,
		severity: json.Get("severity").Str,
		descr:    json.Get("descr").Str,
		code:     json.Get("code").Str,
	}
}

type Device struct {
	json    gjson.Result
	dn      string
	address string
	name    string
	role    string
}

func makeDevice(json gjson.Result) Device {
	return Device{
		json:    json,
		dn:      json.Get("dn").Str,
		address: json.Get("address").Str,
		name:    json.Get("name").Str,
		role:    json.Get("role").Str,
	}
}

type Running struct {
	json    gjson.Result
	version string
}

func makeRunning(json gjson.Result) Running {
	return Running{
		json:    json,
		version: json.Get("version").Str,
	}
}

type Job struct {
	json             gjson.Result
	upgradeStatus    string
	upgradeStatusStr string
	instlProgPct     int64
	fwGrp            string
	desiredVersion   string
	maintGrp         string
}

func makeJob(json gjson.Result) Job {
	return Job{
		json:             json,
		upgradeStatus:    json.Get("upgradeStatus").Str,
		upgradeStatusStr: json.Get("upgradeStatusStr").Str,
		instlProgPct:     json.Get("instlProgPct").Int(),
		fwGrp:            json.Get("fwGrp").Str,
		desiredVersion:   json.Get("desiredVersion").Str,
		maintGrp:         json.Get("maintGrp").Str,
	}
}

type Snapshot struct {
	json    gjson.Result
	faults  []Fault
	devices []Device
}

func makeSnapshot(json gjson.Result) Snapshot {
	var faults []Fault
	var devices []Device
	for _, fault := range json.Get("faults").Array() {
		faults = append(faults, makeFault(fault))
	}
	for _, device := range json.Get("devices").Array() {
		devices = append(devices, makeDevice(device))
	}
	return Snapshot{
		json:    json,
		faults:  faults,
		devices: devices,
	}
}

type Status struct {
	device  Device
	job     Job
	running Running
}

const (
	stable = iota + 1
	upgrading
)

func (f Fabric) url(fragment string) string {
	return fmt.Sprintf("https://%s%s.json", f.options.IP, fragment)
}

func (f Fabric) refresh() error {
	_, err := f.get("/api/aaaRefresh")
	return err
}

func (f Fabric) get(fragment string) (gjson.Result, error) {
	url := f.url(fragment)
	log.WithFields(logrus.Fields{
		"type": "GET",
		"uri":  fragment,
	})
	log.WithFields(logrus.Fields{
		"type": "GET",
		"uri":  fragment,
	}).Debug()
	res, err := f.client.Get(url)
	if err != nil {
		return gjson.Result{}, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return gjson.Result{}, err
	}
	return gjson.GetBytes(body, "imdata"), nil
}

func (f Fabric) login() error {
	fragment := "/api/aaaLogin"
	url := f.url(fragment)
	data := fmt.Sprintf(`{"aaaUser":{"attributes":{"name":"%s","pwd":"%s"}}}`,
		f.options.Username, f.options.Password)
	log.WithFields(logrus.Fields{
		"type":     "POST",
		"fragment": fragment,
	}).Debug()
	res, err := f.client.Post(url, "json", strings.NewReader(data))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("HTTP response: %s.", res.Status))
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	errText := gjson.GetBytes(body, "imdata|0|error|attributes|text").Str
	if errText != "" {
		return errors.New("Authentication error")
	}
	log.Info("Authentication successful.")
	return nil
}

func input(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ", prompt)
	input, _ := reader.ReadString('\n')
	return strings.Trim(input, "\r\n")
}

func getArgs() Args {
	args := Args{Snapshot: "snapshot.json"}
	arg.MustParse(&args)
	if args.IP == "" {
		args.IP = input("APIC IP:")
	}
	if args.Username == "" {
		args.Username = input("Username:")
	}
	if args.Password == "" {
		fmt.Print("Password: ")
		pwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		args.Password = string(pwd)
	}
	return args
}

func (Args) Description() string {
	return "Monitor ACI health status."
}

func (Args) Version() string {
	if Rev == "" {
		return fmt.Sprintf("Version %s local build", Version)
	}
	return fmt.Sprintf("Version %s Revision %s", Version, Rev)
}

func (f Fabric) getDevices() (res []Device) {
	devices, _ := f.get("/api/class/topSystem")
	for _, device := range devices.Get("#.topSystem.attributes").Array() {
		res = append(res, makeDevice(device))
	}
	return
}

func (f Fabric) getFaults() (res []Fault) {
	faults, _ := f.get("/api/class/faultInfo")
	for _, fault := range faults.Get("#.faultInst.attributes").Array() {
		res = append(res, makeFault(fault))
	}
	return
}

func (f Fabric) getAPICStatus(device Device) (Status, error) {
	dn := device.dn
	urlJob := fmt.Sprintf("/api/mo/%s/ctrlrfwstatuscont/upgjob", dn)
	urlRunning := fmt.Sprintf("/api/mo/%s/ctrlrfwstatuscont/ctrlrrunning", dn)
	job, err := f.get(urlJob)
	if err != nil {
		return Status{}, err
	}
	running, err := f.get(urlRunning)
	if err != nil {
		return Status{}, err
	}
	return Status{
		device:  device,
		job:     makeJob(job.Get("0|maintUpgJob|attributes")),
		running: makeRunning(running.Get("0|firmwareCtrlrRunning|attributes")),
	}, nil
}

func (f Fabric) getSwitchStatus(device Device) (Status, error) {
	dn := device.dn
	urlJob := fmt.Sprintf("/api/mo/%s/fwstatuscont/upgjob", dn)
	urlRunning := fmt.Sprintf("/api/mo/%s/fwstatuscont/running", dn)
	job, err := f.get(urlJob)
	if err != nil {
		return Status{}, err
	}
	running, err := f.get(urlRunning)
	if err != nil {
		return Status{}, err
	}
	return Status{
		device:  device,
		job:     makeJob(job.Get("0|maintUpgJob|attributes")),
		running: makeRunning(running.Get("0|firmwareRunning|attributes")),
	}, nil
}

func (f Fabric) getUpgradeStatus(devices []Device) (res []Status, err error) {
	log.Info("Querying devices for upgrade state. Please wait...")
	for _, device := range devices {
		switch device.role {
		case "controller":
			status, err := f.getAPICStatus(device)
			if err != nil {
				return res, err
			}
			res = append(res, status)
		case "leaf", "spine":
			status, err := f.getSwitchStatus(device)
			if err != nil {
				return res, err
			}
			res = append(res, status)
		case "remote-leaf-wan":
			log.WithFields(logrus.Fields{
				"message": "Unsupported remote leaf",
				"device":  device.name,
			}).Warn()
		case "virtual":
			log.WithFields(logrus.Fields{
				"message": "Unsupported virtual leaf",
				"device":  device.name,
			}).Warn()
		default:
			log.WithFields(logrus.Fields{
				"message": "Unrecognized device type",
				"device":  device.name,
			}).Warn()
		}
	}
	return res, nil
}

func createNewSnapshot(f Fabric, fn string) Snapshot {
	log.Info(fmt.Sprintf("Creating new snapshot %s...", fn))
	var faultJSON string
	faults := f.getFaults()
	for _, fault := range faults {
		faultJSON += fault.json.Raw
	}
	var deviceJSON string
	devices := f.getDevices()
	for _, device := range devices {
		deviceJSON += device.json.Raw
	}
	data := fmt.Sprintf(`{"faults":[%s],"devices":[%s]}`, faultJSON, deviceJSON)
	prettyData := gjson.Get(data, "@pretty").Raw
	if err := ioutil.WriteFile(fn, []byte(prettyData), 0644); err != nil {
		panic(err)
	}
	return makeSnapshot(gjson.Parse(data))

}

func (f Fabric) readSnapshot() Snapshot {
	fn := f.options.Snapshot
	if _, err := os.Stat(fn); err == nil {
		log.Info(fmt.Sprintf(`Loading snapshot "%s"...`, fn))
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			panic(err)
		}
		return makeSnapshot(gjson.ParseBytes(data))
	} else {
		return createNewSnapshot(f, fn)
	}
}

func (f Fabric) parseUpgradeState(statuses []Status) int {
	sorted := struct {
		scheduled   []Status
		queued      []Status
		upgrading   []Status
		ok          []Status
		failed      []Status
		unavailable []Status
	}{}
	for _, status := range statuses {
		switch status.job.upgradeStatus {
		case "scheduled":
			sorted.scheduled = append(sorted.scheduled, status)
		case "inqueue", "inretryqueue":
			sorted.queued = append(sorted.queued, status)
		case "inprogress", "waitonbootup":
			sorted.upgrading = append(sorted.upgrading, status)
		case "completeok", "notscheduled":
			sorted.ok = append(sorted.ok, status)
		case "incompatible", "completenok":
			sorted.failed = append(sorted.failed, status)
		default:
			sorted.unavailable = append(sorted.unavailable, status)
		}
	}
	if len(sorted.scheduled) > 0 {
		log.Info(fmt.Sprintf("%d device(s) scheduled for upgrade.",
			len(sorted.scheduled)))
		log.Info("Note that these will not start upgrading without a trigger.")
		if !f.options.Verbose {
			log.Info(`Use "verbose" option to view details of scheduled devices.`)
		}
		for _, status := range sorted.scheduled {
			log.WithFields(logrus.Fields{
				"name":              status.device.name,
				"ip":                status.device.address,
				"status":            status.job.upgradeStatus,
				"firmware group":    status.job.fwGrp,
				"current version":   status.running.version,
				"desired version":   status.job.desiredVersion,
				"maintenance group": status.job.maintGrp,
			}).Debug()
		}
	}
	if len(sorted.queued) > 0 {
		log.Warn(fmt.Sprintf("%d device(s) queued for upgrade.",
			len(sorted.queued)))
		log.Warn("The following devices are queued to upgrade automatically...")
		for _, status := range sorted.queued {
			log.WithFields(logrus.Fields{
				"name":              status.device.name,
				"ip":                status.device.address,
				"status":            status.job.upgradeStatus,
				"firmware group":    status.job.fwGrp,
				"current version":   status.running.version,
				"desired version":   status.job.desiredVersion,
				"maintenance group": status.job.maintGrp,
			}).Warn()
		}
	}

	if len(sorted.unavailable) > 0 {
		log.Warn(fmt.Sprintf("%d device(s) are not providing a status.",
			len(sorted.unavailable)))
		log.Info("Devices may be rebooting due to upgrade activity.")
		for _, status := range sorted.unavailable {
			log.WithFields(logrus.Fields{
				"name":   status.device.name,
				"ip":     status.device.address,
				"status": "unknown",
			}).Warn()

		}
	}

	if len(sorted.upgrading) > 0 {
		log.Warn(fmt.Sprintf("%d device(s) upgrading.", len(sorted.upgrading)))
		var percents []int
		for _, status := range sorted.upgrading {
			percent := status.job.instlProgPct
			if percent > 0.0 {
				percents = append(percents, int(percent))
			}
			log.WithFields(logrus.Fields{
				"name":              status.device.name,
				"ip":                status.device.address,
				"status":            status.job.upgradeStatus,
				"percent":           status.job.instlProgPct,
				"firmware group":    status.job.fwGrp,
				"current version":   status.running.version,
				"desired version":   status.job.desiredVersion,
				"maintenance group": status.job.maintGrp,
			}).Warn()
		}
		if len(percents) > 0 {
			var total int
			for _, percent := range percents {
				total += percent
			}
			avg := int(float64(total) / float64(len(percents)))
			log.Info(fmt.Sprintf("Average total percent: %d%%", avg))
		}
	}

	if len(sorted.queued) == 0 &&
		len(sorted.upgrading) == 0 &&
		len(sorted.unavailable) == 0 {
		log.Info("No devices currently undergoing upgrade.")
		return stable
	}
	return upgrading
}

func (f Fabric) checkFaults(faults []Fault) {
	var newFaults []Fault
	for _, currentFault := range f.getFaults() {
		newFault := true
		for _, previousFault := range faults {
			if previousFault.dn == currentFault.dn {
				newFault = false
			}
		}
		if newFault && currentFault.severity != "cleared" {
			newFaults = append(newFaults, currentFault)
		}
	}
	if len(newFaults) > 0 {
		log.Warn(fmt.Sprintf("%d new fault(s) since previous snapshot.",
			len(newFaults)))
		for _, fault := range newFaults {
			log.WithFields(logrus.Fields{
				"Code":        fault.code,
				"Severity":    fault.severity,
				"Description": fault.descr,
			}).Warn()
		}
	} else {
		log.Info("No new faults since snapshot.")
	}
}

func (f Fabric) requestLoop(snapshot Snapshot) error {
	lastRefresh := time.Now()
	for {
		if time.Since(lastRefresh) >= (8 * time.Minute) {
			err := f.refresh()
			if err != nil {
				return err
			}
		}
		if f.options.Upgrade {
			statuses, err := f.getUpgradeStatus(snapshot.devices)
			if err != nil {
				return err
			}
			if f.parseUpgradeState(statuses) == stable {
				f.checkFaults(snapshot.faults)
			}
		} else {
			f.checkFaults(snapshot.faults)
		}
		log.Info("Sleeping for 10 seconds...")
		time.Sleep(10 * time.Second)
	}
}

func (f Fabric) loginLoop() (ok bool) {
	err := f.login()
	for err != nil {
		log.Error(err)
		log.Info("Note, that login failures are expected on device reload.")
		log.Info("If this is the initial login, hit Ctrl-C and verify login details.")
		log.Info("Waiting 60 seconds before trying again...")
		time.Sleep(60 * time.Second)
		err = f.login()
	}
	return true
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logrus.SetOutput(colorable.NewColorableStdout())
	log = logrus.New()
}

func main() {
	f := makeFabric()
	log.Info("Hit Ctrl-C to stop")
	f.loginLoop()
	snapshot := f.readSnapshot()
	for {
		if err := f.requestLoop(snapshot); err != nil {
			log.Error(err)
		}
		f.loginLoop()
	}
}
