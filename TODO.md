# 📝 honeyPot Project TODO

## High Priority
- [ ] Implement more fake endpoints (e.g. `/onvif/device_service`, `/web/login`, `/admin`, `/ISAPI/System/deviceInfo`)
- [ ] Reduce 404s by mapping more URLs to realistic responses
- [ ] Add more device profiles (Dahua, TP-Link, etc.)
- [ ] Enhance protocol emulation for ONVIF, RTSP, FTP, SSH, MQTT

## Medium Priority
- [ ] Log all HTTP requests, not just known endpoints
- [ ] Add more honeytoken files and credentials
- [ ] Integrate with external threat feeds (AbuseIPDB, VirusTotal, Shodan)
- [ ] Improve dashboard analytics (attack chains, timelines, top honeytokens)
- [ ] Add more usage examples and screenshots to README

## Low Priority / Stretch Goals
- [ ] Optimize for higher traffic (async IO, better logging)
- [ ] Containerize honeypot for easy deployment (Docker)
- [ ] Add machine learning-based anomaly detection
- [ ] Export logs to ELK/Splunk/SIEM
- [ ] Add automated endpoint and logging tests (CI)

---

**Tip:**  
Check off items as you complete them by changing `[ ]` to `[x]`.
