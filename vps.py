import os
import re
import time
import shutil
import secrets
import string
from pylxd import Client
from pylxd.exceptions import LXDAPIException, NotFound as LXDNotFound

# Matches the "Link:  https://sshx.io/s/xxxx#yyyy" line sshx prints on start.
# Restricted to the actual charset sshx uses (base62 id, base64url-ish key)
# rather than \S+, which would also swallow trailing ANSI color-reset codes
# (e.g. "\x1b[0m") that sshx prints right after the link — those aren't
# whitespace, so a greedy \S+ silently appends them onto the URL/key and
# produces a link sshx.io then rejects as "invalid end-to-end encryption key".
SSHX_LINK_RE = re.compile(r"https://sshx\.io/s/[A-Za-z0-9]+#[A-Za-z0-9_-]+")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

client = Client()

IMAGE_ALIAS = os.environ.get("VPS_IMAGE_ALIAS", "ubuntu/22.04")

STORAGE_POOL = os.environ.get("VPS_STORAGE_POOL", "zfs-new")

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_host_capacity():
    cpu_cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram_mb = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass

    real_disk_gb = None
    try:
        usage = shutil.disk_usage("/")
        real_disk_gb = usage.total // (1024 ** 3)
    except Exception:
        pass

    return {
        "cpu_cores": cpu_cores,
        "ram_mb": ram_mb,
        "disk_budget_gb": TOTAL_DISK_BUDGET_GB,
        "disk_allocated_gb": get_allocated_disk_gb(),
        "real_disk_gb": real_disk_gb,
    }


TOTAL_DISK_BUDGET_GB = 6 * 1024  # 6TB

# Standard RAM grant per VPS, in MB. Changed to 100GB per request.
STANDARD_VPS_RAM_MB = 100 * 1024  # 102400 MB = 100GB


def _quota_gb(inst):
    try:
        size = inst.devices.get("root", {}).get("size", "")
        if size.upper().endswith("GB"):
            return int(size[:-2])
        elif size.upper().endswith("TB"):
            return int(size[:-2]) * 1024
    except Exception:
        pass
    return 0


def get_allocated_disk_gb():
    total_bytes = 0
    for inst in client.instances.all():
        if not inst.name.startswith("vps-"):
            continue

        usage_bytes = None
        try:
            state = inst.state()
            usage_bytes = (state.disk or {}).get("root", {}).get("usage")
        except Exception:
            usage_bytes = None

        if usage_bytes:
            total_bytes += usage_bytes
        else:
            total_bytes += _quota_gb(inst) * (1024 ** 3)

    return total_bytes // (1024 ** 3)


MIN_FREE_DISK_GB = 100


def can_allocate_disk(additional_gb):
    allocated = get_allocated_disk_gb()
    budget_ok = (allocated + additional_gb) <= TOTAL_DISK_BUDGET_GB

    real_free_gb = None
    try:
        usage = shutil.disk_usage("/")
        real_free_gb = usage.free // (1024 ** 3)
    except Exception:
        pass

    safety_ok = real_free_gb is None or real_free_gb >= MIN_FREE_DISK_GB

    if not safety_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, (
            f"Only {real_free_gb}GB free on the physical disk (minimum "
            f"{MIN_FREE_DISK_GB}GB kept in reserve) — refusing new allocations "
            f"until space actually frees up, even though the budget has room."
        )
    if not budget_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, None

    return True, allocated, TOTAL_DISK_BUDGET_GB, None


def get_container(container_id):
    try:
        return client.instances.get(container_id)
    except LXDNotFound:
        return None
    except Exception:
        return None


def _wait_running(inst, timeout=30):
    waited = 0
    while waited < timeout:
        inst.sync()
        if inst.status.lower() == "running":
            return True
        time.sleep(1)
        waited += 1
    return False


MAX_TOTAL_VPS = 150


def count_all_vps():
    return sum(1 for inst in client.instances.all() if inst.name.startswith("vps-"))


def can_create_vps():
    current = count_all_vps()
    return current < MAX_TOTAL_VPS, current


def create_vps(username, cpu_limit=1, ram_limit_mb=STANDARD_VPS_RAM_MB, disk_limit_gb=10, image=IMAGE_ALIAS):
    password = generate_password()
    container_name = f"vps-{username}-{secrets.token_hex(3)}"

    config = {
        "name": container_name,
        "source": {
            "type": "image",
            "alias": image,
        },
        "config": {
            "limits.cpu": str(cpu_limit),
            "limits.memory": f"{ram_limit_mb}MB",
            "limits.memory.enforce": "hard",
            "security.nesting": "true",
            "security.privileged": "true",
            "security.syscalls.intercept.mknod": "true",
            "security.syscalls.intercept.setxattr": "true",
            "linux.kernel_modules": "overlay,br_netfilter",
        },
        "devices": {
            "root": {
                "path": "/",
                "pool": STORAGE_POOL,
                "type": "disk",
                "size": f"{disk_limit_gb}GB",
            }
        },
    }

    try:
        inst = client.instances.create(config, wait=True)
        inst.start(wait=True)

        if not _wait_running(inst):
            raise RuntimeError("Container did not reach running state in time")

        _set_root_password_with_retry(inst, password)

        return {
            "container_id": container_name,
            "container_name": container_name,
            "ssh_port": None,
            "password": password,
            "status": "running",
        }
    except LXDAPIException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def _exec(inst, cmd_list, environment=None):
    return inst.execute(cmd_list, environment=environment or {})


def _set_root_password(inst, password):
    try:
        _exec(inst, ["bash", "-c", f"echo root:{password} | chpasswd"])
    except Exception as e:
        print(f"Failed setting password: {e}")


def _set_root_password_with_retry(inst, password, attempts=15, delay=2):
    last_err = None
    for _ in range(attempts):
        try:
            _exec(inst, ["bash", "-c", f"echo root:{password} | chpasswd"])
            return
        except Exception as e:
            last_err = e
            time.sleep(delay)
    print(f"Failed setting password after {attempts} attempts: {last_err}")


def start_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.start(wait=True)
    return {"status": "started"}


def stop_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.stop(wait=True, timeout=10)
    return {"status": "stopped"}


def restart_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.restart(wait=True, timeout=10)
    return {"status": "restarted"}


def _parse_mem_mb(raw):
    try:
        raw = raw.upper().strip()
        if raw.endswith("GB"):
            return int(raw[:-2]) * 1024
        if raw.endswith("MB"):
            return int(raw[:-2])
    except Exception:
        pass
    return None


def get_vps_specs(container_id):
    inst = get_container(container_id)
    if not inst:
        return None
    cpu_raw = inst.config.get("limits.cpu", "4")
    try:
        cpu_cores = int(cpu_raw)
    except Exception:
        cpu_cores = 4
    ram_mb = _parse_mem_mb(inst.config.get("limits.memory", f"{STANDARD_VPS_RAM_MB}MB")) or STANDARD_VPS_RAM_MB
    disk_gb = _quota_gb(inst) or STANDARD_VPS_DISK_GB
    return {"cpu_cores": cpu_cores, "ram_mb": ram_mb, "disk_gb": disk_gb}


def reinstall_vps(container_id, username):
    specs = get_vps_specs(container_id) or {
        "cpu_cores": 4, "ram_mb": STANDARD_VPS_RAM_MB, "disk_gb": STANDARD_VPS_DISK_GB
    }
    try:
        delete_vps(container_id)
    except Exception:
        pass
    return create_vps_container(
        username,
        cpu_limit=specs["cpu_cores"],
        ram_limit_mb=specs["ram_mb"],
        disk_limit_gb=specs["disk_gb"],
    )


def delete_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    try:
        if inst.status.lower() == "running":
            inst.stop(wait=True, timeout=10)
    except Exception:
        pass
    inst.delete(wait=True)
    return {"status": "deleted"}


def destroy_vps(container_id):
    return delete_vps(container_id)


def regenerate_ssh(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    new_password = generate_password()
    try:
        _exec(inst, ["bash", "-c", f"echo root:{new_password} | chpasswd"])
        _exec(inst, ["bash", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A"])
        return {"status": "regenerated", "password": new_password}
    except Exception as e:
        return {"error": str(e)}


def get_vps_status(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"status": "not_found"}
    inst.sync()
    return {
        "status": inst.status.lower(),
        "name": inst.name,
    }


def sync_status(container_id, db_status):
    if db_status not in ("running", "stopped"):
        return db_status
    real = get_vps_status(container_id).get("status")
    if real in ("running", "stopped"):
        return real
    return db_status


def list_all_vps():
    out = []
    for inst in client.instances.all():
        if inst.name.startswith("vps-"):
            inst.sync()
            out.append({
                "id": inst.name,
                "name": inst.name,
                "status": inst.status.lower(),
            })
    return out


def exec_in_vps(container_id, cmd):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    result = _exec(inst, ["bash", "-c", cmd])
    return {
        "exit_code": result.exit_code,
        "output": (result.stdout or "") + (result.stderr or ""),
    }


# --- Bridge functions expected by app.py / monitor.py ---

def create_vps_container(username, cpu_limit=4, ram_limit_mb=STANDARD_VPS_RAM_MB, disk_limit_gb=80, image=IMAGE_ALIAS):
    allowed, current = can_create_vps()
    if not allowed:
        raise RuntimeError(
            f"Node VPS limit reached ({current}/{MAX_TOTAL_VPS}). "
            f"No new VPS can be created until existing ones are deleted."
        )

    result = create_vps(username, cpu_limit, ram_limit_mb, disk_limit_gb, image)
    if "error" in result:
        raise RuntimeError(result["error"])

    inst = get_container(result["container_id"])

    sshx_ready = False
    for attempt in range(3):
        if _install_sshx(inst):
            sshx_ready = True
            break
        time.sleep(5)
    if not sshx_ready:
        raise RuntimeError("Could not install sshx inside the container after 3 attempts")

    session_url = None
    for attempt in range(3):
        session_url = _start_sshx_session(inst)
        if session_url:
            break
        time.sleep(3)

    if not session_url:
        raise RuntimeError("sshx installed but a session could not be established after 3 attempts")

    return result["container_id"], session_url


def _install_sshx(inst):
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
    find_cmd = (
        "command -v sshx || "
        "for p in /root/.local/bin/sshx /usr/local/bin/sshx /usr/bin/sshx; do "
        "  [ -x \"$p\" ] && echo \"$p\" && break; "
        "done"
    )

    try:
        check = _exec(inst, ["bash", "-c", find_cmd], environment=env)
        found_path = (check.stdout or "").strip()
        if found_path:
            _ensure_symlinked(inst, found_path, env)
            return True

        curl_check = _exec(inst, ["bash", "-c", "command -v curl"], environment=env)
        if not (curl_check.stdout or "").strip():
            if not _apt_install_with_retry(inst, "curl", env):
                return False

        install_cmd = (
            "curl --retry 3 --retry-delay 2 --retry-connrefused "
            "--connect-timeout 10 -sSf https://sshx.io/get | sh"
        )
        result = None
        for attempt in range(3):
            result = _exec(inst, ["bash", "-c", install_cmd], environment=env)
            if result.exit_code == 0:
                break
            print(f"sshx install script attempt {attempt + 1}/3 exited {result.exit_code}. "
                  f"stdout: {(result.stdout or '').strip()[:500]} "
                  f"stderr: {(result.stderr or '').strip()[:500]}")
            time.sleep(2)

        check2 = _exec(inst, ["bash", "-c", find_cmd], environment=env)
        found_path = (check2.stdout or "").strip()
        if not found_path:
            print(f"sshx not found after install attempts. Last exit_code={result.exit_code if result else None}, "
                  f"stdout={(result.stdout or '').strip()[:500] if result else ''}, "
                  f"stderr={(result.stderr or '').strip()[:500] if result else ''}")
            return False

        _ensure_symlinked(inst, found_path, env)
        return True
    except Exception as e:
        print(f"Failed installing sshx: {e}")
        return False


def _ensure_symlinked(inst, found_path, env):
    if found_path == "/usr/local/bin/sshx":
        return
    try:
        _exec(inst, ["bash", "-c", f"ln -sf '{found_path}' /usr/local/bin/sshx"], environment=env)
    except Exception as e:
        print(f"Could not symlink sshx into /usr/local/bin (non-fatal): {e}")


def _apt_install_with_retry(inst, package, env, attempts=5, wait_seconds=4):
    wait_for_lock = (
        "for i in $(seq 1 30); do "
        "  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; "
        "  sleep 1; "
        "done"
    )
    for attempt in range(attempts):
        _exec(inst, ["bash", "-c", wait_for_lock], environment=env)
        result = _exec(
            inst, ["bash", "-c", f"apt-get update -qq && apt-get install -y -qq {package}"],
            environment=env,
        )
        if result.exit_code == 0:
            return True
        print(f"apt install {package} attempt {attempt + 1}/{attempts} exited {result.exit_code}: "
              f"{(result.stderr or '').strip()[:500]}")
        time.sleep(wait_seconds)
    return False


def _start_sshx_session(inst):
    try:
        _exec(inst, ["bash", "-c", "pkill sshx 2>/dev/null; rm -f /tmp/sshx.log; true"])
        _exec(inst, ["bash", "-c",
                     "NO_COLOR=1 TERM=dumb nohup sshx > /tmp/sshx.log 2>&1 < /dev/null & disown"])

        url = None
        for _ in range(10):
            time.sleep(1)
            result = _exec(inst, ["bash", "-c", "cat /tmp/sshx.log 2>/dev/null || true"])
            clean_log = ANSI_ESCAPE_RE.sub("", result.stdout or "")
            match = SSHX_LINK_RE.search(clean_log)
            if match:
                url = match.group(0)
                break
        return url
    except Exception as e:
        print(f"Failed starting sshx: {e}")
        return None


def regen_sshx(container_id):
    inst = get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    return _start_sshx_session(inst)


def suspend_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    try:
        inst.freeze(wait=True)
    except Exception:
        inst.stop(wait=True, timeout=10)
    return {"status": "suspended"}


def unsuspend_vps(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.sync()
    try:
        if inst.status.lower() == "frozen":
            inst.unfreeze(wait=True)
        else:
            inst.start(wait=True)
    except Exception as e:
        return {"error": str(e)}
    return {"status": "running"}


PORT_FORWARD_RANGE = (20000, 29999)


def _all_used_host_ports():
    used = set()
    for inst in client.instances.all():
        try:
            inst.sync()
            for dev in inst.devices.values():
                if dev.get("type") == "proxy":
                    listen = dev.get("listen", "")
                    parts = listen.split(":")
                    if len(parts) >= 3:
                        try:
                            used.add((parts[0], int(parts[-1])))
                        except ValueError:
                            pass
        except Exception:
            continue
    return used


def add_port_forward(container_id, container_port, protocol="tcp", preferred_host_port=None, retries=3):
    inst = get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    if protocol not in ("tcp", "udp"):
        raise RuntimeError("Protocol must be tcp or udp")
    if not (1 <= container_port <= 65535):
        raise RuntimeError("Invalid container port")

    inst.sync()
    used = _all_used_host_ports()

    host_port = None
    if preferred_host_port and (protocol, preferred_host_port) not in used \
            and PORT_FORWARD_RANGE[0] <= preferred_host_port <= PORT_FORWARD_RANGE[1]:
        host_port = preferred_host_port
    elif (protocol, container_port) not in used and PORT_FORWARD_RANGE[0] <= container_port <= PORT_FORWARD_RANGE[1]:
        host_port = container_port
    else:
        for p in range(*PORT_FORWARD_RANGE):
            if (protocol, p) not in used:
                host_port = p
                break
    if not host_port:
        raise RuntimeError("No free host ports available on this node right now")

    device_name = f"fwd-{protocol}-{host_port}"
    last_error = None
    for attempt in range(retries):
        try:
            inst.sync()
            inst.devices[device_name] = {
                "type": "proxy",
                "listen": f"{protocol}:0.0.0.0:{host_port}",
                "connect": f"{protocol}:127.0.0.1:{container_port}",
            }
            inst.save(wait=True)
            return host_port, device_name
        except Exception as e:
            last_error = e
            time.sleep(2)

    raise RuntimeError(f"Failed to add port forward after {retries} attempts: {last_error}")


def remove_port_forward(container_id, device_name, retries=3):
    inst = get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")

    last_error = None
    for attempt in range(retries):
        try:
            inst.sync()
            if device_name not in inst.devices:
                return False
            del inst.devices[device_name]
            inst.save(wait=True)
            return True
        except Exception as e:
            last_error = e
            time.sleep(2)

    raise RuntimeError(f"Failed to remove port forward after {retries} attempts: {last_error}")


def list_port_forwards(container_id):
    inst = get_container(container_id)
    if not inst:
        return []
    inst.sync()
    out = []
    for name, dev in inst.devices.items():
        if dev.get("type") == "proxy":
            out.append({"device_name": name, "listen": dev.get("listen"), "connect": dev.get("connect")})
    return out


def suspend(container_id):
    return suspend_vps(container_id)


_cpu_sample_cache = {}


def get_container_stats(container_id, created_at=None):
    inst = get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")

    inst.sync()
    raw = inst.state()

    mem_usage = raw.memory.get("usage", 0) if raw.memory else 0
    mem_limit_bytes = 0
    try:
        cfg = inst.config.get("limits.memory", "0MB")
        num = int(''.join(ch for ch in cfg if ch.isdigit()) or 0)
        mem_limit_bytes = num * 1024 * 1024
    except Exception:
        pass

    try:
        num_cpus = int(inst.config.get("limits.cpu", "1"))
    except Exception:
        num_cpus = 1

    cpu_ns_now = raw.cpu.get("usage", 0) if raw.cpu else 0
    t_now = time.time()

    cpu_percent = 0.0
    prev = _cpu_sample_cache.get(container_id)
    if prev:
        cpu_ns_prev, t_prev = prev
        elapsed_ns = (t_now - t_prev) * 1e9
        cpu_delta_ns = cpu_ns_now - cpu_ns_prev
        if elapsed_ns > 0 and cpu_delta_ns >= 0:
            cpu_percent = (cpu_delta_ns / (elapsed_ns * num_cpus)) * 100.0

    _cpu_sample_cache[container_id] = (cpu_ns_now, t_now)

    mem_percent = (mem_usage / mem_limit_bytes * 100.0) if mem_limit_bytes else 0.0
    uptime_seconds = int(time.time() - created_at) if created_at else None

    return {
        "cpu_percent": round(cpu_percent, 2),
        "mem_usage_mb": round(mem_usage / (1024 * 1024), 1),
        "mem_limit_mb": round(mem_limit_bytes / (1024 * 1024), 1),
        "mem_percent": round(mem_percent, 2),
        "uptime_seconds": uptime_seconds,
    }


_SAFE_PROCESS_WHITELIST = [
    "sshx", "sshd", "systemd", "systemd-journald", "systemd-logind",
    "apt", "apt-get", "dpkg", "unattended-upgrade", "cron", "bash",
    "python3", "app.py", "monitor.py", "vps.py", "gunicorn", "flask",
    "init", "dbus-daemon", "rsyslogd", "networkd-dispatcher",
]

_MINER_PROCESS_SIGNATURES = [
    "xmrig", "xmr-stak", "cpuminer", "minerd", "cryptonight",
    "nicehash", "ethminer", "t-rex", "lolminer", "phoenixminer",
    "srbminer", "teamredminer", "unmineable", "kdevtmpfsi", "kinsing",
]

_MINER_PORTS = ["3333", "4444", "5555", "7777", "8080", "9999", "14444", "45700"]

_MINER_ACTIVATION_PATTERNS = [
    "--donate-level", "--cpu-priority", "-o stratum+tcp", "stratum+tcp://",
    "stratum+ssl://", "--algo=", "-a randomx", "-a rx/0", "--coin=monero",
    "--pool=", "-o pool.", "xmrig -o", "xmrig --url",
]


def _process_is_whitelisted(process_line):
    line_lower = process_line.lower()
    return any(safe in line_lower for safe in _SAFE_PROCESS_WHITELIST)


def _check_command_history(inst):
    findings = []
    try:
        result = _exec(inst, [
            "bash", "-c",
            "cat /root/.bash_history 2>/dev/null; "
            "cat /home/*/.bash_history 2>/dev/null; "
            "fc -ln -100 2>/dev/null"
        ])
        history = (result.stdout or "").lower()
        for pattern in _MINER_ACTIVATION_PATTERNS:
            if pattern.lower() in history:
                findings.append(f"activation command in history: '{pattern}'")
    except Exception:
        pass

    try:
        result = _exec(inst, ["bash", "-c", "ps -eo args --no-headers"])
        cmdlines = (result.stdout or "").lower()
        for pattern in _MINER_ACTIVATION_PATTERNS:
            if pattern.lower() in cmdlines:
                findings.append(f"activation command in running process: '{pattern}'")
    except Exception:
        pass

    return findings


def check_for_mining(container_id):
    inst = get_container(container_id)
    if not inst:
        return {"suspected": False, "confidence": "low", "reasons": ["container not found"], "raw": {}}

    weak_reasons = []
    raw = {}

    try:
        result = _exec(inst, ["bash", "-c", "ps aux"])
        ps_output = result.stdout or ""
        raw["ps"] = ps_output[:2000]
        for line in ps_output.lower().splitlines():
            if _process_is_whitelisted(line):
                continue
            for sig in _MINER_PROCESS_SIGNATURES:
                if sig in line:
                    weak_reasons.append(f"process name match: '{sig}' in line: {line.strip()[:120]}")
    except Exception as e:
        raw["ps_error"] = str(e)

    try:
        result = _exec(inst, [
            "bash", "-c",
            "ps -eo pid,pcpu,comm,args --sort=-pcpu | head -n 10"
        ])
        top_procs = result.stdout or ""
        raw["top_procs"] = top_procs
        suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/.", "/run/"]
        for line in top_procs.splitlines()[1:]:
            if _process_is_whitelisted(line):
                continue
            if any(p in line for p in suspicious_paths):
                weak_reasons.append(f"high-cpu process from suspicious path: {line.strip()[:120]}")
    except Exception as e:
        raw["top_procs_error"] = str(e)

    try:
        result = _exec(inst, ["bash", "-c", "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null"])
        conns = result.stdout or ""
        raw["connections"] = conns[:2000]
        for port in _MINER_PORTS:
            if f":{port}" in conns and not _process_is_whitelisted(conns):
                weak_reasons.append(f"outbound connection on common mining port {port}")
    except Exception as e:
        raw["connections_error"] = str(e)

    strong_reasons = _check_command_history(inst)
    raw["activation_check"] = strong_reasons

    if strong_reasons:
        return {
            "suspected": True,
            "confidence": "high",
            "reasons": strong_reasons,
            "raw": raw,
        }
    elif len(weak_reasons) >= 2:
        return {
            "suspected": True,
            "confidence": "low",
            "reasons": weak_reasons,
            "raw": raw,
        }
    else:
        return {
            "suspected": False,
            "confidence": "low",
            "reasons": weak_reasons,
            "raw": raw,
        }


def handle_high_cpu(container_id, threshold=90.0):
    stats = get_container_stats(container_id)
    if stats["cpu_percent"] < threshold:
        return {"action": "none", "cpu_percent": stats["cpu_percent"]}

    mining_check = check_for_mining(container_id)

    if mining_check["suspected"] and mining_check["confidence"] == "high":
        suspend_result = suspend_vps(container_id)
        return {
            "action": "suspended",
            "cpu_percent": stats["cpu_percent"],
            "confidence": "high",
            "reasons": mining_check["reasons"],
            "suspend_result": suspend_result,
        }

    if mining_check["suspected"] and mining_check["confidence"] == "low":
        return {
            "action": "flagged_for_review",
            "cpu_percent": stats["cpu_percent"],
            "confidence": "low",
            "reasons": mining_check["reasons"],
        }

    return {
        "action": "none",
        "cpu_percent": stats["cpu_percent"],
        "note": "high CPU but no mining evidence found — left running",
    }


def stats(container_id):
    s = get_container_stats(container_id)
    return {
        "cpu": s["cpu_percent"],
        "mem_percent": s["mem_percent"],
        "mem_usage_mb": s["mem_usage_mb"],
        "mem_limit_mb": s["mem_limit_mb"],
    }


def build_logs_stream(container_id, follow_seconds=20):
    inst = get_container(container_id)
    if not inst:
        yield "Container not found"
        return
    try:
        result = _exec(inst, ["bash", "-c", "tail -n 100 /var/log/syslog 2>/dev/null || echo 'no logs yet'"])
        for line in (result.stdout or "").splitlines():
            yield line
    except Exception as e:
        yield f"Could not read logs: {e}"
