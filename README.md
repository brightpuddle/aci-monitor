# ACI status monitor tool

Precompiled binaries are provided for all major platforms.

https://github.com/brightpuddle/aci-monitor/releases

## Overview
This tool monitors ongoing health of an ACI fabric. It does this by taking a snapshot of faults before a change and doing a continuous comparison to check for any new faults. Additionally, with the `--upgrade` flag, the script will monitor the current upgrade status across the fabric and only compare faults once upgrades are stable/complete.

Faults are triggered for a wide variety of events, including ISIS adjacency issues, internal MP-BGP adjancencies, COOP sync, environmental factors, etc, so this tool will identify *most* health conditions surrounding a change event. The primary exceptions are events that do not generate faults, e.g. an unexpected change in the number of MAC addresses, routes, etc.

## Usage
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
Display additional logging info to the terminal, e.g. each HTTP request, etc.

`-s --snapshot`
Filename for the snapshot. The default is `snapshot.json`. As the name implies, this file is in JSON, and pretty printed for human-readibility. It contains a list of active devices and faults on the network at the point when created. The recommendation is to create a new snapshot surrounding a change or upgrade to ensure post-change status hasn't introduced any additional faults.

`--upgrade`
Monitor upgrade status of APICs and switches.

## Future
* Tests
* Option to timestamp and rotate log files
* Check for variance in non-fault metrics, e.g. delta change in routes, CAM table, etc


Pull requests and/or feedback welcome.

