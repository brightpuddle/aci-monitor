package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	_ "github.com/konsorten/go-windows-terminal-sequences"
	"github.com/mattn/go-colorable"
	"github.com/orandin/lumberjackrus"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh/terminal"
)

const Version = "0.2.0"

var Rev string
var log *logrus.Logger
var options Options

type JSON = gjson.Result

////////////////////////////////////////////////////////////
// HTTP Client
////////////////////////////////////////////////////////////

type Client struct {
	client *http.Client
}

type Query struct {
	uri   string
	query []string
}

func NewClient() Client {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		log.Panic(err)
	}
	httpClient := http.Client{
		Timeout: time.Second * 30,
		Jar:     cookieJar,
	}
	return Client{
		client: &httpClient,
	}
}

func (c Client) NewURL(q Query) string {
	res := fmt.Sprintf("https://%s%s.json", options.IP, q.uri)
	if len(q.query) > 0 {
		return fmt.Sprintf("%s?%s", res, strings.Join(q.query, "&"))
	}
	return res
}

func (c Client) get(query Query) (JSON, error) {
	url := c.NewURL(query)
	log.Debug(fmt.Sprintf("GET request to %s", query.uri))
	res, err := c.client.Get(url)
	if err != nil {
		return JSON{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return JSON{}, errors.New(fmt.Sprintf(
			"HTTP response: %s.", res.Status))
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return JSON{}, err
	}
	return gjson.GetBytes(body, "imdata"), nil
}

func (c Client) login() error {
	uri := "/api/aaaLogin"
	url := c.NewURL(Query{uri: uri})
	data := fmt.Sprintf(`{"aaaUser":{"attributes":{"name":"%s","pwd":"%s"}}}`,
		options.Username, options.Password)
	log.Debug(fmt.Sprintf("GET request to %s", uri))
	res, err := c.client.Post(url, "json", strings.NewReader(data))
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

func (c Client) refresh() error {
	_, err := c.get(Query{uri: "/api/aaaRefresh"})
	return err
}

////////////////////////////////////////////////////////////
// Logger
////////////////////////////////////////////////////////////

func NewLogger() *logrus.Logger {
	logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logrus.SetOutput(colorable.NewColorableStdout())
	logger := logrus.New()
	if options.Verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logger.SetOutput(colorable.NewColorableStdout())
	hook, err := lumberjackrus.NewHook(
		&lumberjackrus.LogFile{
			Filename:   "aci-monitor.log",
			MaxSize:    100,
			MaxBackups: 1,
			MaxAge:     1,
			Compress:   true,
		},
		logrus.InfoLevel,
		&logrus.JSONFormatter{},
		&lumberjackrus.LogFileOpts{},
	)
	if err != nil {
		panic(err)
	}
	logger.AddHook(hook)
	return logger
}

////////////////////////////////////////////////////////////
// Device
////////////////////////////////////////////////////////////

type Device struct {
	json    JSON
	address string
	dn      string
	name    string
	podId   string
	role    string
}

func NewDevice(json JSON) (device Device, ok bool) {
	device = Device{
		json:    json,
		address: json.Get("address").Str,
		dn:      json.Get("dn").Str,
		name:    json.Get("name").Str,
		podId:   json.Get("podId").Str,
		role:    json.Get("role").Str,
	}
	switch device.role {
	case "remote-leaf-wan":
		log.WithFields(logrus.Fields{
			"device": device.name,
		}).Warn("Ignoring unsupported remote leaf")
	case "virtual":
		log.WithFields(logrus.Fields{
			"device": device.name,
		}).Warn("Ignoring unsupported virtual leaf")
	case "leaf", "spine", "controller":
		// 4.x
		if device.json.Get("virtualMode").Str != "yes" {
			return device, true
		}
	default:
		log.WithFields(logrus.Fields{
			"device": device.name,
		}).Warn("Ignorning unrecognized device type")
	}
	return device, false
}

func (d Device) MarshalJSON() ([]byte, error) {
	return []byte(d.json.Raw), nil
}

func (c Client) getDevices() (res []Device, err error) {
	devices, err := c.get(Query{uri: "/api/class/topSystem"})
	if err != nil {
		return
	}
	for _, record := range devices.Get("#.topSystem.attributes").Array() {
		if device, ok := NewDevice(record); ok {
			res = append(res, device)
		}
	}
	return
}

////////////////////////////////////////////////////////////
// Fault
////////////////////////////////////////////////////////////

type Fault struct {
	json     JSON
	code     string
	descr    string
	dn       string
	severity string
}

func NewFault(json JSON) Fault {
	return Fault{
		json:     json,
		code:     json.Get("code").Str,
		descr:    json.Get("descr").Str,
		dn:       json.Get("dn").Str,
		severity: json.Get("severity").Str,
	}
}

func (f Fault) MarshalJSON() ([]byte, error) {
	return []byte(f.json.Raw), nil
}

func (c Client) getFaults() (res []Fault, err error) {
	faults, err := c.get(Query{uri: "/api/class/faultInfo"})
	if err != nil {
		return
	}
	for _, fault := range faults.Get("#.faultInst.attributes").Array() {
		res = append(res, NewFault(fault))
	}
	return
}

type FaultsByCode = map[string][]Fault

func appendFaultByCode(byCode FaultsByCode, fault Fault) FaultsByCode {
	if faults, ok := byCode[fault.code]; ok {
		byCode[fault.code] = append(faults, fault)
	} else {
		byCode[fault.code] = []Fault{fault}
	}
	return byCode
}

func verifyFaults(faults []Fault, currentFaults []Fault) {

	var faultsByCode = make(FaultsByCode)
	var newFaultCount int
	for _, currentFault := range currentFaults {
		newFault := true
		for _, previousFault := range faults {
			if previousFault.dn == currentFault.dn {
				newFault = false
			}
		}
		if newFault && currentFault.severity != "cleared" {
			faultsByCode = appendFaultByCode(faultsByCode, currentFault)
			newFaultCount += 1
		}
	}
	if newFaultCount > 0 {
		log.Warn(fmt.Sprintf("%d new fault(s) since previous snapshot.",
			newFaultCount))
		if !options.Verbose {
			log.Info("Use verbose mode to see full fault list.")
		}
		for _, faults := range faultsByCode {
			if options.Verbose {
				for i, fault := range faults {
					log.WithFields(logrus.Fields{
						"code":        fault.code,
						"severity":    fault.severity,
						"description": fault.descr,
						"count":       fmt.Sprintf("%d of %d", i, len(faults)),
					}).Warn("new fault")
				}
			} else {
				fault := faults[0]
				log.WithFields(logrus.Fields{
					"code":        fault.code,
					"severity":    fault.severity,
					"description": fault.descr,
					"count":       len(faults),
				}).Warn(fmt.Sprintf("%d new %s fault(s)", len(faults), fault.code))
			}
		}
	} else {
		log.Info("No new faults since snapshot.")
	}
}

////////////////////////////////////////////////////////////
// Pod
////////////////////////////////////////////////////////////

type Pod struct {
	json    JSON
	dn      string
	podId   string
	tepPool string
}

func (p Pod) MarshalJSON() ([]byte, error) {
	return []byte(p.json.Raw), nil
}

func NewPod(json JSON) Pod {
	return Pod{
		json:    json,
		dn:      json.Get("dn").Str,
		podId:   json.Get("podId").Str,
		tepPool: json.Get("tepPool").Str,
	}
}

func (c Client) getPods() (res []Pod, err error) {
	pods, err := c.get(Query{uri: "/api/class/fabricSetupP"})
	if err != nil {
		return
	}
	for _, pod := range pods.Get("#.fabricSetupP.attributes").Array() {
		switch pod.Get("podType").Str {
		case "physical":
			res = append(res, NewPod(pod))
		case "virtual":
			log.WithFields(logrus.Fields{
				"pod": pod.Get("podId").Str,
			}).Debug("Ignoring unsupported virtual pod")
		}
	}
	return
}

////////////////////////////////////////////////////////////
// ISISRoute
////////////////////////////////////////////////////////////

type ISISRoute struct {
	json JSON
	dn   string
}

func (r ISISRoute) MarshalJSON() ([]byte, error) {
	return []byte(r.json.Raw), nil
}

func NewISISRoute(json JSON) ISISRoute {
	return ISISRoute{
		json: json,
		dn:   json.Get("dn").Str,
	}
}

func (c Client) getISISRoutes(pods []Pod) (res []ISISRoute, err error) {
	var tepQueries []string
	for _, pod := range pods {
		queryString := fmt.Sprintf(`eq(isisRoute.pfx,"%s")`, pod.tepPool)
		tepQueries = append(tepQueries, queryString)
	}
	routes, err := c.get(Query{
		uri: "/api/node/class/isisRoute",
		query: []string{
			"rsp-subtree-include=relations",
			fmt.Sprintf("query-target-filter=or(%s)", strings.Join(tepQueries, ",")),
		},
	})
	if err != nil {
		return
	}
	for _, record := range routes.Get("#.isisNexthop.attributes").Array() {
		res = append(res, NewISISRoute(record))
	}
	return
}

func verifyInterpodRoutes(fabric Fabric, currentRoutes []ISISRoute) {
	var convergingCount int
	for _, device := range fabric.devices {
		if device.role != "leaf" {
			continue
		}
		var expectedRoutes int
		for _, route := range fabric.isisRoutes {
			if strings.HasPrefix(route.dn, device.dn) {
				expectedRoutes++
			}
		}
		var routes int
		for _, route := range currentRoutes {
			if strings.HasPrefix(route.dn, device.dn) {
				routes++
			}
		}
		switch {
		case routes < expectedRoutes:
			convergingCount++
			log.WithFields(logrus.Fields{
				"name":            device.name,
				"expected routes": expectedRoutes,
				"actual routes":   routes,
			}).Warn("Less IPN routes than in snapshot")
		case routes > expectedRoutes:
			log.WithFields(logrus.Fields{
				"name":            device.name,
				"expected routes": expectedRoutes,
				"actual routes":   routes,
			}).Warn("More IPN routes than in snapshot")
			log.Warn("Snapshot appears to have missing routes")
		default:
			log.WithFields(logrus.Fields{
				"name":            device.name,
				"expected routes": expectedRoutes,
				"actual routes":   routes,
			}).Debug("IPN routes to all spines")
		}
	}
	if convergingCount == 0 {
		log.Info("IPN routes fully converged.")
	}
}

////////////////////////////////////////////////////////////
// Upgrade Status
////////////////////////////////////////////////////////////

type Status struct {
	device  Device
	job     MaintUpgJob
	running FirmwareRunning
}

const (
	stable = iota + 1
	upgrading
)

type MaintUpgJob struct {
	json             JSON
	dn               string
	desiredVersion   string
	fwGrp            string
	instlProgPct     int64
	maintGrp         string
	upgradeStatus    string
	upgradeStatusStr string
}

func (c Client) getMaintUpgJob() (res []MaintUpgJob, err error) {
	json, err := c.get(Query{uri: "/api/class/maintUpgJob"})
	if err != nil {
		return res, err
	}
	for _, record := range json.Get("#.maintUpgJob.attributes").Array() {
		res = append(res, MaintUpgJob{
			json:             record,
			dn:               record.Get("dn").Str,
			desiredVersion:   record.Get("desiredVersion").Str,
			fwGrp:            record.Get("fwGrp").Str,
			instlProgPct:     record.Get("instlProgPct").Int(),
			maintGrp:         record.Get("maintGrp").Str,
			upgradeStatus:    record.Get("upgradeStatus").Str,
			upgradeStatusStr: record.Get("upgradeStatusStr").Str,
		})
	}
	return res, nil
}

type FirmwareRunning struct {
	json    JSON
	dn      string
	version string
}

func (c Client) getFirmwareRunning() (res []FirmwareRunning, err error) {
	json, err := c.get(Query{uri: "/api/class/firmwareRunning"})
	if err != nil {
		return res, err
	}
	records := json.Get("#.firmwareRunning.attributes").Array()
	for _, record := range records {
		res = append(res, FirmwareRunning{
			json:    record,
			dn:      record.Get("dn").Str,
			version: record.Get("version").Str,
		})
	}
	return res, nil
}

func (c Client) getFirmwareCtrlrRunning() (res []FirmwareRunning, err error) {
	json, err := c.get(Query{uri: "/api/class/firmwareCtrlrRunning"})
	if err != nil {
		return res, err
	}
	records := json.Get("#.firmwareCtrlrRunning.attributes").Array()
	for _, record := range records {
		res = append(res, FirmwareRunning{
			json:    record,
			dn:      record.Get("dn").Str,
			version: record.Get("version").Str,
		})
	}
	return res, nil
}

func (c Client) getUpgradeStatuses(devices []Device) (res []Status, err error) {
	log.Info("Querying devices for upgrade state. Please wait...")
	maintUpgJobs, err := c.getMaintUpgJob()
	if err != nil {
		return res, err
	}
	firmwareRunnings, err := c.getFirmwareRunning()
	if err != nil {
		return res, err
	}
	firmwareCtrlrRunnings, err := c.getFirmwareCtrlrRunning()
	if err != nil {
		return res, err
	}
	for _, device := range devices {
		var firmwareRunningArray []FirmwareRunning
		var firmwareRunningDN, maintUpgJobDN string
		status := Status{device: device}
		switch device.role {
		case "controller":
			firmwareRunningDN = device.dn + "/ctrlfwstatuscont/ctrlrrunning"
			maintUpgJobDN = device.dn + "/ctrlrfwstatuscont/upgjob"
			firmwareRunningArray = firmwareCtrlrRunnings
		case "leaf", "spine":
			firmwareRunningDN = device.dn + "/fwstatuscont/running"
			maintUpgJobDN = device.dn + "/fwstatuscont/upgjob"
			firmwareRunningArray = firmwareRunnings
		}
		for _, firmwareRunning := range firmwareRunningArray {
			if firmwareRunning.dn == firmwareRunningDN {
				status.running = firmwareRunning
				break
			}
		}
		for _, maintUpgJob := range maintUpgJobs {
			if maintUpgJob.dn == maintUpgJobDN {
				status.job = maintUpgJob
				break
			}
		}
		res = append(res, status)
	}
	return
}

func verifyUpgradeState(statuses []Status) int {
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
		log.Info("verbose option will show details of scheduled devices.")
		for _, status := range sorted.scheduled {
			log.WithFields(logrus.Fields{
				"name":              status.device.name,
				"ip":                status.device.address,
				"status":            status.job.upgradeStatus,
				"firmware group":    status.job.fwGrp,
				"current version":   status.running.version,
				"desired version":   status.job.desiredVersion,
				"maintenance group": status.job.maintGrp,
			}).Debug("Device scheduled for upgrade")
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
			}).Warn("Device queued for upgrade")
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
			}).Warn("Device has unknown upgrade status")

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
			}).Warn("Device upgrading")
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

////////////////////////////////////////////////////////////
// Fabric Snapshot
////////////////////////////////////////////////////////////

type Fabric struct {
	json       JSON
	faults     []Fault
	devices    []Device
	pods       []Pod
	isisRoutes []ISISRoute
	timestamp  time.Time
}

func NewFabric(json JSON) Fabric {
	var faults []Fault
	var devices []Device
	var pods []Pod
	var isisRoutes []ISISRoute
	for _, record := range json.Get("faults").Array() {
		faults = append(faults, NewFault(record))
	}
	for _, record := range json.Get("devices").Array() {
		if device, ok := NewDevice(record); ok {
			devices = append(devices, device)
		}
	}
	for _, record := range json.Get("pods").Array() {
		pods = append(pods, NewPod(record))
	}
	for _, record := range json.Get("isisRoutes").Array() {
		isisRoutes = append(isisRoutes, NewISISRoute(record))
	}
	return Fabric{
		json:       json,
		faults:     faults,
		devices:    devices,
		pods:       pods,
		isisRoutes: isisRoutes,
		timestamp:  time.Now(),
	}
}

func (f Fabric) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"faults":     f.faults,
		"devices":    f.devices,
		"pods":       f.pods,
		"isisRoutes": f.isisRoutes,
		"timestamp":  f.timestamp,
	})
}

func (c Client) getFabric() Fabric {
	var faults []Fault
	var devices []Device
	var pods []Pod
	var isisRoutes []ISISRoute
	for ok := false; !ok; {
		// Don't write file until data has been fetched successfully
		var err error
		faults, err = c.getFaults()
		devices, err = c.getDevices()
		pods, err = c.getPods()
		isisRoutes, err = c.getISISRoutes(pods)
		if err != nil {
			log.Error(err)
		} else {
			ok = true
		}
	}
	return Fabric{
		faults:     faults,
		devices:    devices,
		pods:       pods,
		isisRoutes: isisRoutes,
		timestamp:  time.Now(),
	}
}

func (c Client) createNewSnapshot(fn string, fabric Fabric) Fabric {
	prettyData, _ := json.MarshalIndent(fabric, "", "  ")
	if err := ioutil.WriteFile(fn, prettyData, 0644); err != nil {
		log.Panic(err)
	}
	return fabric
}

func (c Client) readSnapshot() (fabric Fabric) {
	fn := options.Snapshot
	if _, err := os.Stat(fn); err == nil {
		log.Info(fmt.Sprintf(`Loading snapshot "%s"...`, fn))
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Panic(err)
		}
		json := gjson.ParseBytes(data)
		fabric = NewFabric(json)
		var currentFabric Fabric
		var fetched bool
		getFabricsOnce := func() Fabric {
			if !fetched {
				currentFabric = c.getFabric()
				fetched = true
			}
			return currentFabric
		}
		if !json.Get("faults").Exists() {
			fabric.faults = getFabricsOnce().faults
		}
		if !json.Get("devices").Exists() {
			fabric.devices = getFabricsOnce().devices
		}
		if !json.Get("pods").Exists() {
			fabric.pods = getFabricsOnce().pods
		}
		if !json.Get("timestamp").Exists() {
			fabric.timestamp = getFabricsOnce().timestamp
		}
		if !json.Get("isisRoutes").Exists() {
			fabric.isisRoutes = getFabricsOnce().isisRoutes
		}
		if fetched {
			log.Info(fmt.Sprintf("Updating snapshot %s...", fn))
			c.createNewSnapshot(fn, fabric)
		}
	} else {
		log.Info(fmt.Sprintf("Creating new snapshot %s...", fn))
		fabric = c.createNewSnapshot(fn, c.getFabric())
	}
	return
}

////////////////////////////////////////////////////////////
// Options
////////////////////////////////////////////////////////////

type Options struct {
	IP       string `arg:"-i" help:"fabric IP address"`
	Password string `arg:"-p"`
	Snapshot string `arg:"-s" help:"Snapshot file"`
	// Upgrade  bool   `arg:"--upgrade" help:"Monitor upgrade status"`
	Username string `arg:"-u"`
	Verbose  bool   `arg:"-v"`
}

func (Options) Description() string {
	return "Monitor ACI health status."
}

func (Options) Version() string {
	if Rev == "" {
		return fmt.Sprintf("Version %s local build", Version)
	}
	return fmt.Sprintf("Version %s Revision %s", Version, Rev)
}

func input(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ", prompt)
	input, _ := reader.ReadString('\n')
	return strings.Trim(input, "\r\n")
}

func getOptions() Options {
	args := Options{Snapshot: "snapshot.json"}
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

////////////////////////////////////////////////////////////
// Main execution flow
////////////////////////////////////////////////////////////

func (c Client) requestLoop(fabric Fabric) error {
	lastRefresh := time.Now()
	for {
		if time.Since(lastRefresh) >= (8 * time.Minute) {
			if err := c.refresh(); err != nil {
				return err
			}
		}
		statuses, err := c.getUpgradeStatuses(fabric.devices)
		if err != nil {
			return err
		}
		if verifyUpgradeState(statuses) == stable {
			currentFaults, err := c.getFaults()
			if err != nil {
				return err
			}
			verifyFaults(fabric.faults, currentFaults)
			if len(fabric.pods) > 1 {
				isisRoutes, err := c.getISISRoutes(fabric.pods)
				if err != nil {
					return err
				}
				verifyInterpodRoutes(fabric, isisRoutes)
			}
		}
		log.Info("Sleeping for 10 seconds...")
		time.Sleep(10 * time.Second)
	}
}

func (c Client) loginLoop() (ok bool) {
	err := c.login()
	for err != nil {
		log.Error(err)
		log.Info("Note, that login failures are expected on device reload.")
		log.Info("If this is the initial login, hit Ctrl-C and verify login details.")
		log.Info("Waiting 60 seconds before trying again...")
		time.Sleep(60 * time.Second)
		err = c.login()
	}
	return true
}

func init() {
	options = getOptions()
	log = NewLogger()
}

func main() {
	c := NewClient()
	log.Info("Running: Hit Ctrl-C to stop")
	c.loginLoop()
	fabric := c.readSnapshot()
	for {
		if err := c.requestLoop(fabric); err != nil {
			log.Error(err)
		}
		c.loginLoop()
	}
}
