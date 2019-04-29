package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh/terminal"
)

const version = "0.2.0"

var log *logrus.Logger
var client *apiClient

type apiClient struct {
	httpClient *http.Client
	cfg        *Config
}

type apiReq struct {
	uri   string
	query []string
}

type apiRes = gjson.Result

func input(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s ", prompt)
	input, _ := reader.ReadString('\n')
	return strings.Trim(input, "\r\n")
}

func newClient(cfg *Config) *apiClient {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		log.Panic(err)
	}
	httpClient := http.Client{
		Timeout: time.Second * time.Duration(cfg.RequestTimeout),
		Jar:     cookieJar,
	}
	return &apiClient{
		httpClient: &httpClient,
		cfg:        cfg,
	}
}

func newURL(req apiReq) string {
	result := fmt.Sprintf("https://%s%s.json", client.cfg.IP, req.uri)
	if len(req.query) > 0 {
		return fmt.Sprintf("%s?%s", result, strings.Join(req.query, "&"))
	}
	return result
}

func (api *apiClient) getURI(uri string) (apiRes, error) {
	return api.get(apiReq{uri: uri})
}

func (api *apiClient) get(req apiReq) (apiRes, error) {
	url := newURL(req)
	log.Debug(fmt.Sprintf("GET request to %s", req.uri))
	httpRes, err := api.httpClient.Get(url)
	if err != nil {
		return apiRes{}, err
	}
	defer httpRes.Body.Close()
	if httpRes.StatusCode != http.StatusOK {
		return apiRes{}, fmt.Errorf("HTTP response: %s", httpRes.Status)
	}
	body, err := ioutil.ReadAll(httpRes.Body)
	if err != nil {
		return apiRes{}, err
	}
	return apiRes(gjson.GetBytes(body, "imdata")), nil
}

func (api *apiClient) login() error {
	uri := "/api/aaaLogin"
	url := newURL(apiReq{uri: uri})
	data := fmt.Sprintf(`{"aaaUser":{"attributes":{"name":"%s","pwd":"%s"}}}`,
		api.cfg.Username, api.cfg.Password)
	log.Debug(fmt.Sprintf("GET request to %s", uri))
	res, err := api.httpClient.Post(url, "json", strings.NewReader(data))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP response: %s", res.Status)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	errText := gjson.GetBytes(body, "imdata|0|error|attributes|text").Str
	if errText != "" {
		return errors.New("authentication error")
	}
	log.Info("Authentication successful.")
	return nil
}

func (api *apiClient) refresh() error {
	_, err := api.getURI("/api/aaaRefresh")
	return err
}

func newLogger(cfg *Config) *logrus.Logger {
	logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logrus.SetOutput(colorable.NewColorableStdout())
	logger := logrus.New()
	if cfg.Verbose {
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

type deviceObject struct {
	json    apiRes
	address string
	dn      string
	name    string
	podID   string
	role    string
}

func newDevice(json apiRes) (device deviceObject, ok bool) {
	device = deviceObject{
		json:    json,
		address: json.Get("address").Str,
		dn:      json.Get("dn").Str,
		name:    json.Get("name").Str,
		podID:   json.Get("podId").Str,
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

// MarshalJSON : marshal device
func (d deviceObject) MarshalJSON() ([]byte, error) {
	return []byte(d.json.Raw), nil
}

func getDevices() (res []deviceObject, err error) {
	devices, err := client.get(apiReq{uri: "/api/class/topSystem"})
	if err != nil {
		return
	}
	for _, record := range devices.Get("#.topSystem.attributes").Array() {
		if device, ok := newDevice(record); ok {
			res = append(res, device)
		}
	}
	return
}

type faultObject struct {
	json     apiRes
	code     string
	descr    string
	dn       string
	severity string
}

func newFault(json apiRes) faultObject {
	return faultObject{
		json:     json,
		code:     json.Get("code").Str,
		descr:    json.Get("descr").Str,
		dn:       json.Get("dn").Str,
		severity: json.Get("severity").Str,
	}
}

// MarshalJSON : marshal faultObject
func (f faultObject) MarshalJSON() ([]byte, error) {
	return []byte(f.json.Raw), nil
}

func getFaults() (res []faultObject, err error) {
	faults, err := client.get(apiReq{uri: "/api/class/faultInfo"})
	if err != nil {
		return
	}
	for _, faultObject := range faults.Get("#.faultInst.attributes").Array() {
		res = append(res, newFault(faultObject))
	}
	return
}

type faultsByCode = map[string][]faultObject

func appendFaultByCode(byCode faultsByCode, f faultObject) faultsByCode {
	if faults, ok := byCode[f.code]; ok {
		byCode[f.code] = append(faults, f)
	} else {
		byCode[f.code] = []faultObject{f}
	}
	return byCode
}

func verifyFaults(faults []faultObject, currentFaults []faultObject) {

	var faultsByCode = make(faultsByCode)
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
			newFaultCount++
		}
	}
	if newFaultCount > 0 {
		log.Warn(fmt.Sprintf("%d new fault(s) since previous snapshot.",
			newFaultCount))
		if !client.cfg.Verbose {
			log.Info("Use verbose mode to see full fault list.")
		}
		for _, faults := range faultsByCode {
			if client.cfg.Verbose {
				for i, faultObject := range faults {
					log.WithFields(logrus.Fields{
						"code":        faultObject.code,
						"severity":    faultObject.severity,
						"description": faultObject.descr,
						"count":       fmt.Sprintf("%d of %d", i, len(faults)),
					}).Warn("new fault(s)")
				}
			} else {
				faultObject := faults[0]
				log.WithFields(logrus.Fields{
					"code":        faultObject.code,
					"severity":    faultObject.severity,
					"description": faultObject.descr,
					"count":       len(faults),
				}).Warn(fmt.Sprintf("%d new %s fault(s)", len(faults), faultObject.code))
			}
		}
	} else {
		log.Info("No new faults since snapshot.")
	}
}

type podObject struct {
	json    apiRes
	dn      string
	podID   string
	tepPool string
}

// MarshalJSON : marshal pod
func (p podObject) MarshalJSON() ([]byte, error) {
	return []byte(p.json.Raw), nil
}

func newPod(json apiRes) podObject {
	return podObject{
		json:    json,
		dn:      json.Get("dn").Str,
		podID:   json.Get("podId").Str,
		tepPool: json.Get("tepPool").Str,
	}
}

func getPods() (res []podObject, err error) {
	pods, err := client.getURI("/api/class/fabricSetupP")
	if err != nil {
		return
	}
	for _, pod := range pods.Get("#.fabricSetupP.attributes").Array() {
		switch pod.Get("podType").Str {
		case "physical":
			res = append(res, newPod(pod))
		case "virtual":
			log.WithFields(logrus.Fields{
				"pod": pod.Get("podId").Str,
			}).Debug("Ignoring unsupported virtual pod")
		}
	}
	return
}

type isisRouteObject struct {
	json apiRes
	dn   string
}

// MarshalJSON : marshal isisRoute
func (r isisRouteObject) MarshalJSON() ([]byte, error) {
	return []byte(r.json.Raw), nil
}

func newISISRoute(json apiRes) isisRouteObject {
	return isisRouteObject{
		json: json,
		dn:   json.Get("dn").Str,
	}
}

func getISISRoutes(pods []podObject) (res []isisRouteObject, err error) {
	var tepQueries []string
	for _, pod := range pods {
		queryString := fmt.Sprintf(`eq(isisRoute.pfx,"%s")`, pod.tepPool)
		tepQueries = append(tepQueries, queryString)
	}
	routes, err := client.get(apiReq{
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
		res = append(res, newISISRoute(record))
	}
	return
}

func verifyInterpodRoutes(fabric fabricObject, currentRoutes []isisRouteObject) {
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

type status struct {
	device  deviceObject
	job     maintUpgJob
	running firmwareRunning
}

const (
	stable = iota + 1
	upgrading
)

type maintUpgJob struct {
	json             apiRes
	dn               string
	desiredVersion   string
	fwGrp            string
	instlProgPct     int64
	maintGrp         string
	upgradeStatus    string
	upgradeStatusStr string
}

func getMaintUpgJob() (res []maintUpgJob, err error) {
	json, err := client.getURI("/api/class/maintUpgJob")
	if err != nil {
		return res, err
	}
	for _, record := range json.Get("#.maintUpgJob.attributes").Array() {
		res = append(res, maintUpgJob{
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

type firmwareRunning struct {
	json    apiRes
	dn      string
	version string
}

func getFirmwareRunning() (res []firmwareRunning, err error) {
	json, err := client.getURI("/api/class/firmwareRunning")
	if err != nil {
		return res, err
	}
	records := json.Get("#.firmwareRunning.attributes").Array()
	for _, record := range records {
		res = append(res, firmwareRunning{
			json:    record,
			dn:      record.Get("dn").Str,
			version: record.Get("version").Str,
		})
	}
	return res, nil
}

func getFirmwareCtrlrRunning() (res []firmwareRunning, err error) {
	json, err := client.getURI("/api/class/firmwareCtrlrRunning")
	if err != nil {
		return res, err
	}
	records := json.Get("#.firmwareCtrlrRunning.attributes").Array()
	for _, record := range records {
		res = append(res, firmwareRunning{
			json:    record,
			dn:      record.Get("dn").Str,
			version: record.Get("version").Str,
		})
	}
	return res, nil
}

func getUpgradeStatuses(devices []deviceObject) (res []status, err error) {
	log.Info("Querying devices for upgrade state. Please wait...")
	maintUpgJobs, err := getMaintUpgJob()
	if err != nil {
		return res, err
	}
	firmwareRunnings, err := getFirmwareRunning()
	if err != nil {
		return res, err
	}
	firmwareCtrlrRunnings, err := getFirmwareCtrlrRunning()
	if err != nil {
		return res, err
	}
	for _, device := range devices {
		var firmwareRunningArray []firmwareRunning
		var firmwareRunningDN, maintUpgJobDN string
		status := status{device: device}
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

func verifyUpgradeState(statuses []status) int {
	sorted := struct {
		scheduled   []status
		queued      []status
		upgrading   []status
		ok          []status
		failed      []status
		unavailable []status
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
		log.Info("Note that these will not start upgrading without opts trigger.")
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
		log.Warn(fmt.Sprintf("%d device(s) are not providing opts status.",
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

type fabricObject struct {
	json       apiRes
	faults     []faultObject
	devices    []deviceObject
	pods       []podObject
	isisRoutes []isisRouteObject
	timestamp  time.Time
}

func newFabric(json apiRes) fabricObject {
	var faults []faultObject
	var devices []deviceObject
	var pods []podObject
	var isisRoutes []isisRouteObject
	for _, record := range json.Get("faults").Array() {
		faults = append(faults, newFault(record))
	}
	for _, record := range json.Get("devices").Array() {
		if device, ok := newDevice(record); ok {
			devices = append(devices, device)
		}
	}
	for _, record := range json.Get("pods").Array() {
		pods = append(pods, newPod(record))
	}
	for _, record := range json.Get("isisRoutes").Array() {
		isisRoutes = append(isisRoutes, newISISRoute(record))
	}
	return fabricObject{
		json:       json,
		faults:     faults,
		devices:    devices,
		pods:       pods,
		isisRoutes: isisRoutes,
		timestamp:  time.Now(),
	}
}

// MarshalJSON : marshal fabric
func (f fabricObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"faults":     f.faults,
		"devices":    f.devices,
		"pods":       f.pods,
		"isisRoutes": f.isisRoutes,
		"timestamp":  f.timestamp,
	})
}

func getFabric() fabricObject {
	var faults []faultObject
	var devices []deviceObject
	var pods []podObject
	var isisRoutes []isisRouteObject
	for ok := false; !ok; {
		// Don't write file until data has been fetched successfully
		var err error
		if faults, err = getFaults(); err != nil {
			log.Error(err)
			continue
		}
		if devices, err = getDevices(); err != nil {
			log.Error(err)
			continue
		}
		if pods, err = getPods(); err != nil {
			log.Error(err)
			continue
		}
		if isisRoutes, err = getISISRoutes(pods); err != nil {
			log.Error(err)
			continue
		}
		ok = true
	}
	return fabricObject{
		faults:     faults,
		devices:    devices,
		pods:       pods,
		isisRoutes: isisRoutes,
		timestamp:  time.Now(),
	}
}

func createNewSnapshot(fn string, fabric fabricObject) fabricObject {
	prettyData, _ := json.MarshalIndent(fabric, "", "  ")
	if err := ioutil.WriteFile(fn, prettyData, 0644); err != nil {
		log.Panic(err)
	}
	return fabric
}

func readSnapshot() (fabric fabricObject) {
	fn := client.cfg.Snapshot
	if _, err := os.Stat(fn); err == nil {
		log.Info(fmt.Sprintf(`Loading snapshot "%s"...`, fn))
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Panic(err)
		}
		json := gjson.ParseBytes(data)
		fabric = newFabric(json)
		var currentFabric fabricObject
		var fetched bool
		getFabricsOnce := func() fabricObject {
			if !fetched {
				currentFabric = getFabric()
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
			createNewSnapshot(fn, fabric)
		}
	} else {
		log.Info(fmt.Sprintf("Creating new snapshot %s...", fn))
		fabric = createNewSnapshot(fn, getFabric())
	}
	return
}

// Config : CLI args
type Config struct {
	IP                 string `arg:"-i" help:"APIC IP address"`
	Username           string `arg:"-u" help:"username"`
	Password           string `arg:"-p" help:"password"`
	Snapshot           string `arg:"-s" help:"Snapshot file"`
	Verbose            bool   `arg:"-v"`
	RequestTimeout     int    `arg:"--request-timeout" help:"HTTP request timeout"`
	LoginRetryInterval int    `arg:"--login-retry-interval" help:"Login retry interval"`
}

// Description : App description for CLI interface
func (Config) Description() string {
	return "Monitor ACI health status"
}

// Version : App version string for CLI interface
func (Config) Version() string {
	return fmt.Sprintf("ACI monitor version %s", version)
}

func newConfigFromCLI() Config {
	cfg := Config{
		Snapshot:           "snapshot.json",
		RequestTimeout:     30,
		LoginRetryInterval: 60,
	}
	arg.MustParse(&cfg)
	if cfg.IP == "" {
		cfg.IP = input("APIC IP:")
	}
	if cfg.Username == "" {
		cfg.Username = input("Username:")
	}
	if cfg.Password == "" {
		fmt.Print("Password: ")
		pwd, _ := terminal.ReadPassword(int(syscall.Stdin))
		cfg.Password = string(pwd)
	}
	return cfg
}

func requestLoop(fabric fabricObject) error {
	lastRefresh := time.Now()
	for {
		if time.Since(lastRefresh) >= (8 * time.Minute) {
			if err := client.refresh(); err != nil {
				return err
			}
		}
		statuses, err := getUpgradeStatuses(fabric.devices)
		if err != nil {
			return err
		}
		if verifyUpgradeState(statuses) == stable {
			currentFaults, err := getFaults()
			if err != nil {
				return err
			}
			verifyFaults(fabric.faults, currentFaults)
			if len(fabric.pods) > 1 {
				isisRoutes, err := getISISRoutes(fabric.pods)
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

func loginLoop() (ok bool) {
	for err := client.login(); err != nil; err = client.login() {
		log.Error(err)
		log.Info("Note, that login failures are expected on device reload.")
		log.Info("If this is the initial login, hit Ctrl-C and verify login details.")
		log.Info("Waiting 60 seconds before trying again...")
		time.Sleep(time.Duration(client.cfg.LoginRetryInterval) * time.Second)
	}
	return true
}

func init() {
	cfg := newConfigFromCLI()
	log = newLogger(&cfg)
	client = newClient(&cfg)
}

func main() {
	log.Info("Running: Hit Ctrl-C to stop")
	loginLoop()
	fabric := readSnapshot()
	for {
		if err := requestLoop(fabric); err != nil {
			log.Error(err)
		}
		loginLoop()
	}
}
