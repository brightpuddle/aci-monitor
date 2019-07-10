<p align="center">
<img src="logo.png" width="400" height="85" border="0" alt="ACI vetR collector">
<br/>
ACI Monior
<p>
<hr/>

This tool monitors the health of the fabric throughout a change. It does this by taking a snapshot of key state information (faults, devices, upgrade state, etc) before a change, and notifying of any differences in real time. This would typically be used *in addtion* to other pre/post-checks, e.g. this tool will allow you to see when the fabric is back in the original pre-change state, at which point you can start normal post-change verification.

Note that the tool does not try to determine whether the fabric healthy at the begining of the change, but is used for real-time comparison of pre, during, and post-change state.

Faults are triggered for a wide variety of events, including ISIS adjacency issues, internal MP-BGP adjancencies, COOP sync, environmental factors, etc, so this tool will identify *most* health conditions surrounding a change event. The exceptions are events that do not generate faults, e.g. an unexpected change in the number of MAC addresses, routes, etc. These may be added to the tool in the future, but the current focus is *mostly* faults.

## FAQ

### Why do we need this when we have access to the same information via the GUI/moquery/CLI?

This tool simplifies querying the most important information and displays it a way that's easily consumable. It does this continuously (every 10s by default). In comparison, reviewing the faults manually is prone to error, e.g. missing the one fault that matters.

This tool also monitors upgrade state *throughout* the fabric, which is targeted for inclusion in the GUI in CSCvo12256.

Finally, this tool allows checking for real-time state information that's not easily reviewed through stare-and-compare, e.g. delta change in number of endpoints, etc. At first release, this is minimal and only includes ISIS routes, but may be expanded in the future.

### How does this compare to the state checker app?

State checker is more comprehensive, but doesn't perform ongoing monitoring. The two tools are complimentary in that the state checker could be run before and after a change to provide a more comprehensive diff, and this tool could be run throughout the change to monitor real-time state.

## Security

This tool queries the following API objects:
```
/api/class/topSystem
/api/class/fabricSetupP
/api/class/faultInfo
/api/class/firmwareRunning
/api/class/firmwreCtrlrRunnin
/api/class/isisNextHop
```
All results are saved in JSON format in the `snapshot.json` file. Nothing is saved or communicated across the network outside of this single file.

The tool is open source and all code is available on GitHub. Binaries are published for convenience, but the tool can be compiled from source if required for security purposes.

## Usage
Run this tool surrounding a change. Delete any existing snapshot files at the begining of the change, start the tool and run it through to the end of the change. By running the tool this way you'll be able to see when the fabric returns to the original pre-change fault state.

Precompiled binaries are available for download in the releases tab:

https://github.com/brightpuddle/aci-monitor/releases

All arguments are optional

`-h --help`
Display command line help

`--version`
Build info.

`-u --username`
Username (will prompt if not provided)

`-p --password`
Password (will prompt if not provided)

`-i --ip`
APIC IP (will prompt if not provided)
This can be any APIC in the cluster. HTTPS is assumed (not currently configurable) and invalid certs will be ignored.

`-v --verbose`
Display additional logging info to the terminal, e.g. each individual HTTP request, every fault instead of a collated list of faults by code, etc.

`-s --snapshot`
Filename for the snapshot. The default is `snapshot.json`. As the name implies, this file is in JSON, and pretty printed for human-readibility. It contains a list of active devices and faults on the network at the point when created. The recommendation is to create a new snapshot surrounding a change or upgrade to ensure post-change status hasn't introduced any additional faults.

`--request-timeout`
HTTP request timeout. The default is 30 seconds, which should work for most situations. You may need to increase this for a particularly busy APIC or for a high latency connection, e.g. some international connections.

`--login-retry-interval`
Default login retry. When the tool loses connection to the APIC it attempts to login again every 60 seconds by default. This setting allows adjusting this interval. This was added to allow reducing the number of login attempts against backend AAA servers. This should not need to be adjusted for most situations.


**Note** that the following features were deprecated:

`--upgrade` The tool monitors upgrade status by default now. Querying upgrade status only requires three API calls, so there's minimal overhead in checking this all the time, even in routine (non-upgrade) maintenance.

`--json` The tool now logs JSON data to `aci-monitor.log` and provides log rotation and compression by default. It does this in addition to the standard logging to the console.

## Future
- [x] Timestamp snapshot file
- [x] Remove `--json` option and log json to file by default
- [ ] Tests
- [ ] Check for variance in non-fault metrics, e.g. delta change in routes, CAM table, etc


Pull requests and/or feedback welcome.

