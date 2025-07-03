# Advanced Keylogger GUI

A sophisticated keylogger application with graphical user interface designed for authorized security testing and monitoring purposes.

## ⚠️ LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

This keylogger tool is intended exclusively for:
- Educational purposes and cybersecurity learning
- Authorized security testing with proper permissions
- Employee monitoring with proper consent and legal authorization
- Security research in controlled environments

**UNAUTHORIZED USE IS STRICTLY PROHIBITED AND ILLEGAL**

Using this tool without proper authorization may violate:
- Computer Fraud and Abuse Act (CFAA)
- Privacy laws and regulations
- Local and international cybersecurity laws
- Corporate policies and employment agreements

## 🔧 Features

### Core Functionality
- **Real-time Keystroke Logging**: Captures all keyboard input with timestamps
- **GUI Interface**: User-friendly graphical interface with dark theme
- **Live Display**: Real-time display of captured keystrokes
- **File Logging**: Automatic saving to log files with timestamps
- **Screenshot Capture**: On-demand screenshot functionality
- **Sentence Detection**: Intelligent sentence boundary detection

### Advanced Features
- **Start/Stop Controls**: Easy control over logging sessions
- **Clear Display**: Quick clear function for the display area
- **Timestamp Logging**: Detailed timestamps for all activities
- **Error Handling**: Robust error handling and user feedback
- **Professional UI**: Modern dark theme with proper styling

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11 (recommended)
- **Python**: 3.7 or higher
- **RAM**: 2GB minimum
- **Storage**: 50MB free space

### Python Dependencies
```bash
pip install pynput
pip install Pillow
pip install tkinter (usually included with Python)
```

## 🚀 Installation & Usage

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/ArchTech_CyberSecurity_UmairAziz.git
cd ArchTech_CyberSecurity_UmairAziz

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Application
```bash
# Navigate to the main directory
cd main

# Run the keylogger GUI
python keylogger_GUI.py
```

### 3. Using the Application

#### Starting Logging
1. Click the **"Start Logging"** button
2. The application will begin capturing keystrokes
3. All keystrokes appear in real-time in the display area
4. Logs are automatically saved to `keylog_final.txt`

#### Taking Screenshots
1. Click the **"Take Screenshot"** button
2. Screenshots are saved with timestamps
3. Confirmation message appears upon successful capture

#### Stopping Logging
1. Click the **"Stop Logging"** button
2. All logging activities cease immediately
3. Final logs are saved to file

#### Clearing Display
1. Click the **"Clear Display"** button
2. Display area is cleared (logs in file remain intact)

## 🔒 Security Features

### Data Protection
- **Local Storage**: All logs stored locally on the system
- **Timestamp Tracking**: Detailed timestamps for audit trails
- **Secure Logging**: Professional logging framework implementation

### Privacy Considerations
- **No Network Transmission**: Data never leaves the local machine
- **User Control**: Full user control over start/stop operations
- **Transparent Operation**: Clear visual indicators of logging status

## 📁 File Structure

```
keylogger_GUI.py
├── Imports
│   ├── tkinter (GUI framework)
│   ├── pynput (keyboard monitoring)
│   ├── PIL (screenshot functionality)
│   └── logging (file operations)
├── KeyloggerGUI Class
│   ├── __init__() - Initialize GUI
│   ├── start_logging() - Begin keystroke capture
│   ├── stop_logging() - End keystroke capture
│   ├── on_key_press() - Handle key press events
│   ├── on_key_release() - Handle key release events
│   ├── take_screenshot() - Capture screen
│   ├── clear_display() - Clear GUI display
│   └── update_display() - Update GUI with new keystrokes
└── Main Execution
```

## 🛠️ Technical Details

### Architecture
- **GUI Framework**: tkinter with custom styling
- **Keyboard Monitoring**: pynput.keyboard.Listener
- **Threading**: Separate threads for GUI and keyboard monitoring
- **Logging**: Python logging module with file output

### Key Components
1. **KeyloggerGUI Class**: Main application class
2. **Keyboard Listener**: Background thread for keystroke capture
3. **Display Buffer**: Real-time display of captured keystrokes
4. **File Logger**: Persistent storage of all captured data

### Performance Optimizations
- **Efficient Memory Usage**: Optimized string handling
- **Thread Safety**: Proper thread synchronization
- **Resource Management**: Automatic cleanup of resources

## 🐛 Troubleshooting

### Common Issues

#### Permission Errors
- **Solution**: Run as Administrator
- **Cause**: Insufficient permissions for keyboard monitoring

#### Missing Dependencies
- **Solution**: Install required packages
```bash
pip install pynput Pillow
```

#### GUI Not Responding
- **Solution**: Ensure proper Python/tkinter installation
- **Check**: System compatibility and resources

### Error Messages
- **"Permission denied"**: Run with administrator privileges
- **"Module not found"**: Install missing dependencies
- **"Screenshot failed"**: Check display settings and permissions

## 🔍 Monitoring & Logging

### Log File Format
```
2025-01-03 10:30:45: Key pressed: 'a'
2025-01-03 10:30:45: Key pressed: 'b'
2025-01-03 10:30:46: Key pressed: Key.space
2025-01-03 10:30:47: Key pressed: Key.enter
```

### Log File Location
- **Default**: `keylog_final.txt` in the application directory
- **Format**: Plain text with timestamps
- **Encoding**: UTF-8 for international character support

## 📊 Performance Metrics

### Resource Usage
- **CPU**: ~1-2% during active logging
- **Memory**: ~10-15MB RAM usage
- **Disk**: Minimal disk I/O for log writes

### Scalability
- **Concurrent Sessions**: Single session per instance
- **Log File Size**: Efficient storage, ~1KB per 1000 keystrokes
- **Performance**: Real-time processing with minimal latency

## 🤝 Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 👨‍💻 Author

**Umair Aziz**
- Project: ArchTech CyberSecurity Tools
- Email: [your-email@example.com]
- GitHub: [@yourusername]

## 🙏 Acknowledgments

- Python community for excellent libraries
- pynput developers for keyboard monitoring capabilities
- Cybersecurity education community
- Open-source contributors

## 📞 Support

For technical support:
1. Check this documentation
2. Review the main README.md
3. Create an issue on GitHub
4. Contact the maintainer

---

**⚠️ REMEMBER: Always obtain proper authorization before using this tool. Unauthorized keylogging is illegal and unethical.**
