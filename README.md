# Ultra Boosted V13 2025 - Advanced Instagram Account Creator

Advanced Instagram account creation system with sophisticated anti-detection mechanisms, dynamic IP generation, and comprehensive session management.

## Features

### 🔒 Critical Improvements (2025)
- **✅ Proper Session Management**: Complete session cleanup between accounts - NO carry-over
- **✅ Dynamic IP Generation**: Real-time IP pool with blacklist filtering and health scoring
- **✅ Advanced Fingerprinting**: Synchronized JA3/JA3S, device info, and headers
- **✅ Anti-Checkpoint System**: Human-like timing patterns and behavior simulation
- **✅ Latest OS Versions**: Android 14-15, iOS 17-18, macOS Sonoma/Sequoia

### 🌐 IP Management
- Dynamic IP pool generation from 40+ countries
- Comprehensive Indonesian ISP database (Telkomsel, Indosat, XL, Tri, etc.)
- IP health scoring and blacklist system
- Automatic IP rotation based on performance
- Real-time IP validation

### 🎭 Anti-Detection
- Chrome TLS fingerprint impersonation via curl_cffi
- HTTP/2 support with correct settings
- Synchronized browser fingerprints (JA3, device, headers)
- Human-like timing with beta distribution
- Realistic typing speed simulation (40-60 WPM)
- Reading behavior simulation (200-300 WPM)
- Pre-signup behavior patterns

### 📧 Email Management
- 8 email service providers with automatic fallback
- Services: 1secmail, 10minutemail, Mail.tm, GuerrillaMail, etc.
- Automatic email rotation and cleanup
- OTP retrieval with retry logic

### 📊 Session Management
- Complete session cleanup after each account
- No data carry-over between accounts
- Proper cookie, token, and state management
- Session health monitoring

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## Installation

```bash
# Clone repository
git clone https://github.com/Bucin404/Insta.git
cd Insta

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Usage

The application provides an interactive CLI interface:

1. **Create Single Account**: Create one Instagram account
2. **Create Batch Accounts**: Create multiple accounts (1-50)
3. **Run Diagnostics**: Test all system components
4. **View System Status**: Check performance metrics
5. **Test Systems**: Test individual components
6. **Change Settings**: Modify configuration
7. **View Created Accounts**: List successfully created accounts
8. **Email Service Stats**: View email service statistics
9. **IP Pool Management**: Manage IP pool and blacklist

## Configuration

Default configuration is created on first run. Key settings:
- `email_service`: "auto", "1secmail", "10minutemail", "mailtm", etc.
- `device_type`: "desktop" or "android"
- `location`: Country code (e.g., "ID", "US", "AU") or "random"
- `max_concurrent`: Maximum concurrent account creations (1-5)

## Key Improvements in 2025

### Session Management
- **Before**: Sessions persisted between accounts causing detection
- **After**: Complete session destruction after each account
  - `destroy_session()` in AdvancedSessionManager2025
  - `destroy_session_ip()` in IPStealthSystem2025
  - `destroy_session_email()` in EnhancedEmailManager2025
  - `_destroy_session_completely()` orchestrates all cleanup

### Fingerprinting
- **Updated OS Versions**:
  - Android 14-15 (2024-2025)
  - iOS 17.4-18.1 (2024-2025)
  - macOS Sonoma/Sequoia (14.5-15.0)
- **Latest Device Models**:
  - Samsung Galaxy S24 Ultra
  - iPhone 15 Pro/Pro Max
  - Google Pixel 8/8 Pro
- **Chrome Versions**: 120-136 (2024-2025)

### Anti-Checkpoint
- **Human-like Timing**:
  - Beta distribution for natural randomness
  - Micro-jitter to avoid pattern detection
  - Typing speed simulation (40-60 WPM)
  - Reading behavior (200-300 WPM)
- **Behavioral Patterns**:
  - Landing page viewing
  - Scrolling simulation
  - Hesitation before signup (30% chance)
  - Realistic interaction sequences

### IP Management
- **Health Scoring**: Track IP performance over time
- **Blacklist System**: Prevent reuse of blocked IPs
- **Geographic Diversity**: 40+ countries supported
- **ISP Tracking**: Monitor success rates per ISP

## Architecture

```
main.py (19,700+ lines)
├── Session Management
│   ├── UnifiedSessionManager2025
│   ├── AdvancedSessionManager2025
│   └── Session cleanup on every account
├── IP System
│   ├── AdvancedIPStealthSystem2025
│   ├── UltraStealthIPGenerator2025
│   └── IP blacklist & health scoring
├── Fingerprinting
│   ├── ChromeImpersonateClient (curl_cffi)
│   ├── AdvancedFingerprintSystem2025
│   └── WebRTC/WebGL spoofing
├── Email Management
│   ├── EnhancedEmailManager2025
│   └── 8 email service providers
├── Behavior System
│   ├── APIAntiDetectionTiming
│   ├── Human-like patterns
│   └── Pre-signup simulation
└── Account Creation
    ├── InstagramAccountCreator2025
    └── UltraBoostedV13_2025
```

## Statistics Tracking

The system tracks:
- Total attempts, successes, failures
- Success rate and accounts per hour
- IP pool health and distribution
- ISP success rates
- Email service reliability
- Session statistics

## Files Created

- `accounts_2025.txt`: Created accounts (username|password|email)
- `working_ips.json`: IPs that successfully created accounts
- `checkpoint_ips.json`: IPs that got checkpoint
- `blocked_ips.json`: Blacklisted IPs (never use again)
- `isp_stats.json`: ISP success rate statistics
- `sessions_2025.json`: Saved sessions (optional)

## Security

- No credentials stored in repository
- Session data cleaned between accounts
- IP blacklist prevents reuse of blocked IPs
- All sensitive data stored locally

## Contributing

This is a specialized tool. Contributions should focus on:
- Improving anti-detection mechanisms
- Adding new email service providers
- Enhancing IP generation algorithms
- Updating fingerprints to latest versions

## License

For educational purposes only. Use responsibly and in accordance with Instagram's Terms of Service.

## Disclaimer

This tool is for educational and testing purposes only. Creating fake accounts or violating Instagram's Terms of Service is prohibited. The authors are not responsible for misuse of this software.