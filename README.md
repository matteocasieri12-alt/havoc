# HAVOC

```text
██╗  ██╗ █████╗ ██╗   ██╗ ██████╗  ██████╗
██║  ██║██╔══██╗██║   ██║██╔═══██╗██╔════╝
███████║███████║██║   ██║██║   ██║██║     
██╔══██║██╔══██║╚██╗ ██╔╝██║   ██║██║     
██║  ██║██║  ██║ ╚████╔╝ ╚██████╔╝╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝   ╚═════╝  ╚═════╝
```

**HAVOC** is a modular Python command-line utility engineered for authorized laboratory testing, wireless protocol verification, and local redirect simulation. It provides dynamic runtime configuration and a pre-check-guided execution workflow designed for clarity, repeatability, and defensive validation.

---

## Scope and Authorized Use Notice

This software is provided strictly for educational research, controlled laboratory experimentation, and security verification on networks, access points, and endpoints that you own or for which you hold explicit written authorization.

Unauthorized access, interception, or disruption of networks or devices is prohibited and may violate applicable laws and regulations. The maintainers and contributors accept no liability for misuse or non-compliant deployment.

---

## Features

* **`01) Packet Effect Test (Pre-Check)`**: Validates interface availability, attempts channel configuration when supported by the host system, and transmits a short verification probe sequence to observe channel activity prior to further testing.
* **`02) Deauth (Pre-Check -> Sequence)`**: Runs the pre-check stage first and, upon confirmation, transmits a configurable sequence of IEEE 802.11 deauthentication (`Dot11Deauth`) frames via Scapy.
* **`03) Disassoc (Pre-Check -> Sequence)`**: Runs the pre-check stage first and, upon confirmation, transmits a configurable sequence of IEEE 802.11 disassociation (`Dot11Disas`) frames via Scapy.
* **`04) Evil Twin & Captive Portal`**: Launches a local threaded HTTP server on the configured port to test redirect and portal behavior in an isolated lab environment.
* **`05) Media / Rickroll Redirect`**: Launches a local threaded HTTP server configured to issue HTTP `302` redirects toward a user-defined destination URL.
* **`06) Target & Interface Configuration`**: Allows interactive updates to the target interface, channel, SSID, BSSID, and client MAC address during runtime.
* **`07) Parameter Configuration`**: Allows interactive updates to pre-check probe count, burst count, inter-burst interval, redirect URL, and local server port.

---

## Requirements

* **Python**: `3.10+`
* **Scapy** (optional for raw frame transmission and sniffing; falls back gracefully when unavailable):

```bash
pip install scapy
```

* **Linux Wireless Utilities** (optional, for interface inspection and channel management): `ip`, and `iw` or `iwconfig`.

---

## Installation and Usage

Clone the repository and run the application:

```bash
git clone [https://github.com/matteocasieri12-alt/havoc.git](https://github.com/matteocasieri12-alt/havoc.git)[span_1](start_span)[span_1](end_span)
cd havoc
python3 havoc.py
```

When performing raw wireless frame operations on a monitor-capable interface in an authorized lab, run with elevated privileges:

```bash
sudo python3 havoc.py
```

---

## Contributing

Contributions from the community are welcome, including bug reports, documentation improvements, code quality enhancements, and feature proposals:

1. Fork the repository and create a dedicated feature or fix branch from `main`.
2. Keep changes focused, clean, and well-documented.
3. Verify behavior in an authorized test environment before submitting.
4. Open a Pull Request with a clear summary of the changes and rationale.

Please report security vulnerabilities or sensitive issues responsibly rather than disclosing them in public issues.

---

## License

This project is licensed under the **MIT License** (Copyright © 2026 Matteo Casieri). See the [`LICENSE`](LICENSE) file in the repository root for the full license text.
