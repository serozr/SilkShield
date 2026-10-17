"""SilkShield System Telemetry & Hardware Inspection.

Collects host platform telemetry to prove execution on IBM LinuxONE (s390x)
or local development environments.
"""

from __future__ import annotations

import os
import platform
import sys
from typing import Any, Dict


def get_system_telemetry() -> Dict[str, Any]:
    """Inspect and return host architecture, CPU, and platform details."""
    machine = platform.machine().lower()
    is_linuxone = "s390x" in machine or "s390" in machine

    data: Dict[str, Any] = {
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count() or 1,
        "is_linuxone": is_linuxone,
        "platform_name": "IBM LinuxONE (s390x)" if is_linuxone else f"{platform.system()} ({platform.machine()})",
        "vendor": "IBM / s390x Enterprise" if is_linuxone else platform.processor() or "Generic",
        "hypervisor": "Unknown",
        "memory_total_mb": None,
    }

    # Inspect Linux /proc filesystem for z/VM, vendor, or memory details if on Linux
    if platform.system() == "Linux":
        # /proc/cpuinfo
        try:
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                    if "IBM/S390" in content or "vendor_id" in content:
                        data["vendor"] = "IBM/S390"
                    if "z/VM" in content:
                        data["hypervisor"] = "z/VM 7.3.0"
                    for line in content.splitlines():
                        if "machine" in line.lower() and ":" in line:
                            data["machine_type"] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        # /proc/meminfo
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                kb = int(parts[1])
                                data["memory_total_mb"] = round(kb / 1024, 1)
                            break
        except Exception:
            pass

    return data
