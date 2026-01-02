# 🔍 Elite Port Scanner - World's Best Port Scanner

A professional-grade network port scanner with stunning visuals, advanced features, and comprehensive reporting capabilities.

## ✨ Features

### Core Scanning
- **Multi-threaded Port Scanning**: Up to 65,535 ports with configurable parallelism
- **Service Detection**: Automatic identification of 50+ common services
- **Banner Grabbing**: Extract service version and information banners
- **Severity Classification**: CRITICAL, HIGH, and MEDIUM severity levels
- **Smart Port Lists**: Quick, Common, Web, Database, and All port collections

### Advanced Features
- **Concurrent Scanning**: Blazing fast with 100+ parallel threads
- **Configurable Timeouts**: Per-port timeout customization
- **Signal Handling**: Graceful shutdown on Ctrl+C
- **Port Specification**: Flexible port syntax (22,80,443 or 1-1024 or combinations)
- **Category Grouping**: Organize results by service type

### Beautiful Output
- **Terminal Display**: Color-coded results with professional formatting
- **Severity Indicators**: Visual distinction of critical, high, and medium ports
- **Summary Statistics**: Quick overview of scan results
- **Progress Tracking**: Real-time progress during scanning

### Export Formats
- **JSON Export**: Machine-readable structured data
- **CSV Export**: Spreadsheet-compatible format
- **HTML Reports**: Beautiful, styled web reports with statistics

## 📋 Usage

### Basic Scanning
```bash
# Quick scan (22 common ports)
python3 AV_port.py -t 192.168.1.1 -s quick

# Common scan (all well-known services)
python3 AV_port.py -t example.com -s common

# Web services only
python3 AV_port.py -t 10.0.0.1 -s web

# Database services only
python3 AV_port.py -t server.local -s database
```

### Advanced Scanning
```bash
# Custom port list
python3 AV_port.py -t 192.168.1.1 -p 20-25,80,443,3306

# High parallelism for speed
python3 AV_port.py -t target.com -s common --parallelism 200

# Custom timeout for slow networks
python3 AV_port.py -t 10.0.0.1 -s all --timeout 2.0

# Scan all 65,535 ports (slow but thorough)
python3 AV_port.py -t 192.168.1.1 -s all
```

### Export Results
```bash
# Export to JSON
python3 AV_port.py -t 192.168.1.1 -s common --json results.json

# Export to CSV
python3 AV_port.py -t 192.168.1.1 -s common --csv results.csv

# Export to HTML report
python3 AV_port.py -t 192.168.1.1 -s common --html report.html

# Multiple formats at once
python3 AV_port.py -t target.com -s web --json report.json --csv report.csv --html report.html
```

### Advanced Options
```bash
# Skip banner grabbing (faster scanning)
python3 AV_port.py -t 192.168.1.1 --no-banner

# Quiet output (minimal display)
python3 AV_port.py -t target.com -q
```

## 🎨 Output Examples

### Terminal Output
```
╔═══════════════════════════════════════════════════════════════════════════════╗
║         🔍  ELITE PORT SCANNER TOOL  🔍                                       ║
║              Advanced Network Service Discovery & Enumeration                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝

[*] Scanning 22 ports with 100 threads...
────────────────────────────────────────────────────────────────────────────────
[+] Port    22/tcp OPEN - ssh
[+] Port    80/tcp OPEN - http
[+] Port   443/tcp OPEN - https
[+] Port  3306/tcp OPEN - mysql

✓ Port scan complete in 2.34s - 4 ports open

╔═══════════════════════════════════════════════════════════════════════════════╗
║ SCAN RESULTS - 192.168.1.100                                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

PORT     SERVICE              SEVERITY     BANNER/INFO
─────────────────────────────────────────────────────────────────────────────────
22       ssh                  CRITICAL     OpenSSH 7.4
80       http                 HIGH         Apache/2.4.6
443      https                HIGH         Apache/2.4.6
3306     mysql                CRITICAL     MySQL 5.7.28

═══════════════════════════════════════════════════════════════════════════════
SCAN SUMMARY
═══════════════════════════════════════════════════════════════════════════════

  ● Critical Ports: 2
  ● High Severity:   2
  ● Medium:          0
  ● Total Open:      4
  ● Scan Duration:   2.34s
```

### HTML Report
Beautiful styled web report with:
- Color-coded severity levels
- Statistical cards
- Responsive design
- Service information

## 🔧 Service Categories

- **Critical**: SSH, RDP, MSSQL, MySQL, PostgreSQL, MongoDB
- **Web Services**: HTTP, HTTPS, Alt HTTP ports
- **Mail Services**: SMTP, POP3, IMAP, SMTPS, POP3S, IMAPS
- **Directory Services**: LDAP, LDAPS
- **Database Services**: MSSQL, MySQL, PostgreSQL, MongoDB
- **Remote Access**: SSH, RDP, VNC
- **Monitoring**: SNMP, Elasticsearch
- **Other**: 50+ additional services

## ⚙️ Command Line Options

```
-t, --target HOST           Target host or IP address (REQUIRED)
-p, --ports SPEC            Port specification (e.g., "22,80,443" or "1-1000")
-s, --scan-type TYPE        Scan type: quick, common, web, database, all
--parallelism N             Number of parallel threads (default: 100)
--timeout SECONDS           Connection timeout per port (default: 1.0)
--json FILE                 Export results to JSON
--csv FILE                  Export results to CSV
--html FILE                 Export results to HTML report
--no-banner                 Skip banner grabbing (faster)
-q, --quiet                 Minimal output
```

## 📊 Severity Levels

- **CRITICAL** 🔴: SSH, RDP, Database services (high-risk exposure)
- **HIGH** 🟠: Web services, SMB (moderate risk)
- **MEDIUM** 🟡: Other services (lower risk)

## 🚀 Performance Tips

1. **Increase Parallelism**: Use `--parallelism 200-300` for faster scans
2. **Reduce Timeout**: Use `--timeout 0.5` for fast networks
3. **Skip Banners**: Use `--no-banner` to skip service version detection
4. **Target Specific Ports**: Use `-p` with specific port ranges
5. **Choose Right Scan Type**: Use `-s quick` for common ports only

## 📝 Examples

### Security Assessment
```bash
python3 AV_port.py -t 192.168.1.1 -s common --html security_report.html
```

### Network Inventory
```bash
python3 AV_port.py -t server.example.com -s all --json inventory.json
```

### Quick Service Check
```bash
python3 AV_port.py -t 10.0.0.1 -s quick
```

### Database Server Scan
```bash
python3 AV_port.py -t db-server.local -s database --parallelism 200
```

## ⚠️ Legal Notice

This tool is intended for authorized security testing and network administration only. Unauthorized port scanning may be illegal. Always obtain proper authorization before scanning networks you don't own.

## 🎯 Why This Is The World's Best Port Scanner

✅ **Professional Design**: Beautiful terminal output and HTML reports
✅ **Fast & Efficient**: Multi-threaded with configurable parallelism  
✅ **Feature-Rich**: Service detection, severity classification, multiple exports
✅ **User-Friendly**: Flexible CLI with sensible defaults
✅ **Production-Ready**: Proper error handling and signal management
✅ **Extensible**: Easy to add custom scan types and port lists
✅ **Smart Classification**: Categorizes services by type and risk level
✅ **Export Options**: JSON, CSV, and beautiful HTML reports

---

**Created**: January 2026 | **Status**: Production Ready ✓
