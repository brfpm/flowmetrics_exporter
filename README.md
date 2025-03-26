# 🚀 Flowmetrics Exporter  
*A Prometheus exporter for capturing and monitoring network traffic flows using `pcap`.*

![License](https://img.shields.io/badge/License-Apache%202.0-green)

## 📌 Features
✅ Captures **network flows** (source/destination IPs).  
✅ Tracks **packet count** and **total bytes transferred**.  
✅ Supports **custom BPF filters**.  
✅ Allows **CIDR-based whitelisting & internal traffic filtering**.  
✅ Exposes **Prometheus metrics** .  
✅ Supports **custom configuration via YAML**.  

---

## ⚙️ Installation

### **Run the Exporter**
Download **flowmetrics_exporter** and **config.json** from the [releases tab](https://github.com/brfpm/flowmetrics_exporter/releases) and run:
```bash
sudo ./flowmetrics_exporter -c config.yaml
```

### **Build the Binary**
```bash
git clone https://github.com/brfpm/flowmetrics_exporter.git
cd flowmetrics_exporter
go build -o flowmetrics_exporter .
```

**For cross-compilation using docker (e.g., ARM64):**
```bash
docker run --rm -v "$PWD":/app -w /app golang:bullseye \
    bash -c "dpkg --add-architecture arm64 ;apt update && apt install -y gcc-aarch64-linux-gnu libpcap-dev:arm64 libc6-dev-arm64-cross crossbuild-essential-arm64 && \
    CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64  go build -buildvcs=false -o arm64-flowmetrics_exporter ."
```

## 🛠 Configuration
The exporter uses a YAML file for configuration. Below is an example:
```yaml
exporterAddress: "0.0.0.0"   # Listening address
exporterPort: 10032          # Port for Prometheus metrics

ignoreInternalTraffic: true  # Ignore internal-to-internal connections

cidrInternalList:            # Define internal networks
  - "192.168.0.0/16"
  - "10.0.0.0/8"

cidrIgnorelist:              # Ignore these IP ranges
  - "224.0.0.0/24"           # Multicast

bpfFilter: "src net 192.168.1.0/24"  # BPF filter for packet capture
enableBytesPerFlow: true    # Track bytes per flow
interfaceName: "eth0"       # Network interface
```

## 📊 Prometheus Metrics

| Metric | Description                                            |
| ------ | ------------------------------------------------------ |
| packets_per_flow | Total packets per connection (peerA → peerB) |
| bytes_per_flow   | Total bytes per connection (if enabled)      |


## 📈 Grafana Dashboard
You can import the provided JSON file in Grafana to get a pre-built dashboard.

- Go to **Grafana** → **Dashboards** → **Import**.
- Paste the `dashboard.json` file from this repo.
- Set the Prometheus data source.


