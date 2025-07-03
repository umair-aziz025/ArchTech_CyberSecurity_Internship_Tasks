# Advanced Packet Sniffer GUI

A comprehensive network packet analyzer with modern graphical interface designed for network security analysis and authorized penetration testing.

## ⚠️ LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

This packet sniffer tool is intended exclusively for:
- Educational purposes and network security learning
- Authorized penetration testing with proper permissions
- Network troubleshooting and analysis
- Security research in controlled environments
- Professional network security assessments

**UNAUTHORIZED USE IS STRICTLY PROHIBITED AND ILLEGAL**

Using this tool without proper authorization may violate:
- Computer Fraud and Abuse Act (CFAA)
- Network access policies and agreements
- Privacy laws and regulations
- Local and international cybersecurity laws
- Corporate network policies

## 🔧 Features

### Core Functionality
- **Real-time Packet Capture**: Live network traffic monitoring
- **Protocol Analysis**: Support for TCP, UDP, HTTP, HTTPS, DNS, ARP, ICMP
- **Advanced Filtering**: Custom packet filters and presets
- **Modern GUI**: Professional dark-themed interface with tabs
- **Detailed Packet Inspection**: Complete packet header and payload analysis
- **Statistics Dashboard**: Real-time network statistics and metrics

### Advanced Features
- **Multi-Interface Support**: Automatic detection of network interfaces
- **Web Traffic Analysis**: HTTP/HTTPS URL extraction and DNS query monitoring
- **Search & Filter**: Real-time search through captured packets
- **Export Functionality**: Save captures to various formats
- **Hexdump Analysis**: Raw packet data visualization
- **Administrator Detection**: Automatic privilege checking

### User Interface Features
- **Tabbed Interface**: Organized views for Capture, Statistics, and Web Traffic
- **Responsive Design**: Adaptive layout with proper window management
- **Status Bar**: Real-time status updates and copyright information
- **Error Handling**: Comprehensive error messages and troubleshooting
- **Keyboard Shortcuts**: Quick access to common functions

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11 (recommended)
- **Python**: 3.7 or higher
- **RAM**: 4GB minimum (8GB recommended for heavy traffic)
- **Network**: Active network interface
- **Privileges**: Administrator rights required

### Python Dependencies
```bash
pip install scapy
pip install tkinter (usually included with Python)
pip install threading (usually included with Python)
```

### Additional Requirements
- **Npcap**: Required for Windows packet capture
- **WinPcap**: Alternative packet capture driver
- **Administrator Access**: Essential for low-level network access

## 🚀 Installation & Usage

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/ArchTech_CyberSecurity_UmairAziz.git
cd ArchTech_CyberSecurity_UmairAziz

# Install dependencies
pip install -r requirements.txt

# Install Npcap (Windows)
# Download from: https://npcap.com/
```

### 2. Running the Application
```bash
# Run as Administrator (Required)
# Right-click Command Prompt -> "Run as administrator"

# Navigate to the main directory
cd main

# Run the packet sniffer GUI
python sniffer_GUI.py
```

### 3. Using the Application

#### Starting Packet Capture
1. **Select Network Interface**: Choose from detected interfaces
2. **Choose Filter**: Select from preset filters or create custom
3. **Click "Start Capture"**: Begin monitoring network traffic
4. **View Real-time Data**: Packets appear immediately in the list

#### Interface Selection
- **Automatic Detection**: Interfaces detected with IP addresses
- **Friendly Names**: Clear interface identification
- **Debug Option**: Interface debugging tool available

#### Filter Options
- **All Traffic**: Capture everything (default)
- **HTTP (port 80)**: Web traffic only
- **HTTPS (port 443)**: Secure web traffic
- **DNS (port 53)**: Domain name queries
- **Web Traffic**: Combined HTTP/HTTPS/DNS
- **Custom**: User-defined BPF filters

#### Packet Analysis
1. **Click any packet**: View detailed analysis in bottom pane
2. **Double-click**: Jump to packet details
3. **Search**: Use search box to filter packets
4. **Sort**: Click column headers to sort data

#### Statistics Monitoring
1. **Switch to Statistics Tab**: View real-time metrics
2. **Protocol Breakdown**: See TCP/UDP/ICMP/ARP counts
3. **Traffic Summary**: Monitor total packets and bytes
4. **DNS Queries**: Track domain name resolutions

#### Web Traffic Analysis
1. **Switch to Web Traffic Tab**: View web-specific data
2. **Captured URLs**: See all HTTP URLs accessed
3. **DNS Queries**: Monitor all domain name lookups
4. **Real-time Updates**: Data updates automatically

## 🔒 Security Features

### Network Security
- **Read-only Monitoring**: No packet injection or modification
- **Local Processing**: All analysis performed locally
- **Secure Storage**: Captured data stored securely on local system
- **Permission Validation**: Automatic administrator privilege checking

### Privacy Protection
- **No Data Transmission**: Captured data never leaves the local machine
- **User Control**: Full control over capture start/stop operations
- **Clear Indicators**: Visual status of all capture operations
- **Data Cleanup**: Easy clearing of captured data

## 📁 File Structure

```
sniffer_GUI.py
├── Imports & Theme Configuration
├── Packet Analysis Functions
│   ├── extract_http_info() - HTTP packet analysis
│   ├── extract_dns_info() - DNS query extraction
│   ├── get_packet_info() - General packet information
│   └── format_packet_details() - Detailed packet formatting
├── PacketSnifferApp Class
│   ├── __init__() - Initialize application
│   ├── get_network_interfaces() - Interface detection
│   ├── apply_styles() - GUI styling
│   ├── create_widgets() - GUI creation
│   ├── create_capture_tab() - Main capture interface
│   ├── create_stats_tab() - Statistics display
│   ├── create_web_tab() - Web traffic analysis
│   ├── packet_handler() - Packet processing
│   ├── start_sniffing() - Begin capture
│   ├── stop_sniffing() - End capture
│   └── Various utility methods
└── Main Execution
```

## 🛠️ Technical Details

### Architecture
- **GUI Framework**: tkinter with ttk styling
- **Packet Capture**: Scapy library with threading
- **Data Processing**: Queue-based packet handling
- **Interface**: Tabbed interface with responsive design

### Packet Processing Pipeline
1. **Raw Capture**: Scapy captures packets from interface
2. **Queue Processing**: Packets queued for GUI thread safety
3. **Protocol Analysis**: Packets analyzed for protocol information
4. **Display Update**: GUI updated with packet information
5. **Statistics Update**: Real-time statistics calculation

### Performance Optimizations
- **Threaded Architecture**: Separate threads for capture and GUI
- **Efficient Memory**: Optimized packet storage and processing
- **Batch Processing**: Multiple packets processed per GUI update
- **Resource Management**: Automatic cleanup and memory management

## 🐛 Troubleshooting

### Common Issues

#### Permission Errors
```
Error: "Access denied" or "Permission error"
Solution: Run as Administrator
```

#### Interface Detection Problems
```
Error: No interfaces detected
Solution: 
1. Install Npcap/WinPcap
2. Check network adapter status
3. Use Debug Interfaces button
```

#### Capture Failures
```
Error: "Packet capture failed"
Solution:
1. Verify administrator privileges
2. Check interface selection
3. Disable Windows Defender real-time protection temporarily
4. Try different network interface
```

#### Performance Issues
```
Issue: Slow performance or high CPU usage
Solution:
1. Use more specific filters
2. Reduce capture window
3. Clear display regularly
4. Close other network applications
```

### Debug Tools
- **Debug Interfaces Button**: Comprehensive interface information
- **Interface Information**: IP addresses and status
- **System Information**: Administrator status and recommendations
- **Error Messages**: Detailed error descriptions and solutions

## 🔍 Packet Analysis Capabilities

### Supported Protocols
- **Ethernet II**: Layer 2 frame analysis
- **IPv4**: Internet Protocol version 4
- **TCP**: Transmission Control Protocol
- **UDP**: User Datagram Protocol
- **HTTP**: Hypertext Transfer Protocol
- **HTTPS**: Secure HTTP traffic identification
- **DNS**: Domain Name System queries and responses
- **ARP**: Address Resolution Protocol
- **ICMP**: Internet Control Message Protocol

### Analysis Features
- **Header Inspection**: Complete protocol header analysis
- **Payload Analysis**: Text and hexadecimal payload display
- **Flag Interpretation**: TCP flags and protocol-specific indicators
- **Port Recognition**: Automatic service identification by port
- **URL Extraction**: HTTP URL capture and display
- **DNS Resolution**: Query and response tracking

## 📊 Statistics & Metrics

### Real-time Statistics
- **Total Packets**: Complete packet count
- **Total Bytes**: Cumulative data volume
- **Protocol Breakdown**: TCP/UDP/ICMP/ARP distribution
- **Unique URLs**: HTTP URL tracking
- **DNS Queries**: Domain name resolution monitoring

### Performance Metrics
- **Capture Rate**: Packets per second
- **Data Throughput**: Bytes per second
- **Protocol Distribution**: Percentage breakdown
- **Interface Utilization**: Network interface usage

## 🤝 Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 👨‍💻 Author

**Umair Aziz**
- Project: ArchTech CyberSecurity Tools
- Specialization: Network Security & Packet Analysis
- Email: [your-email@example.com]
- GitHub: [@yourusername]

## 🙏 Acknowledgments

- Scapy development team for excellent packet processing library
- Python tkinter developers for GUI framework
- Network security community for protocols and standards
- Cybersecurity education community
- Open-source contributors and security researchers

## 📞 Support

For technical support:
1. Check this documentation thoroughly
2. Review the main README.md file
3. Use the Debug Interfaces feature in the application
4. Create a detailed issue on GitHub
5. Contact the maintainer for security-related queries

### Support Information to Include
- Operating system and version
- Python version
- Error messages (exact text)
- Network interface information
- Administrator privileges status
- Antivirus software in use

---

**⚠️ REMEMBER: Always obtain proper authorization before analyzing network traffic. Unauthorized packet sniffing is illegal and unethical. Use this tool only on networks you own or have explicit permission to analyze.**
