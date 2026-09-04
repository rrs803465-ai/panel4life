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

# Which LXD storage pool new VPSes get created on. Override with
# VPS_STORAGE_POOL if you migrate to a different pool later (e.g. after
# moving from a dir-backed pool to zfs/btrfs for real usage reporting —
# see get_allocated_disk_gb()'s docstring) — no code edit needed next time,
# just set the env var.
STORAGE_POOL = os.environ.get("VPS_STORAGE_POOL", "zfs-new")

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_host_capacity():
    """
    Reads the physical host's real CPU core count and total RAM. This exists
    because LXD/LXCFS will silently CLAMP what a container sees (via
    virtualized /proc/cpuinfo and /proc/meminfo) to whatever the host
    actually has, if you request more than physically exists — it doesn't
    error, it just quietly gives you less than you asked for. That looks
    like a bug from inside the container (e.g. a 104GB/10-core grant showing
    up as 64GB/8-core), but it's really the host's real ceiling. Checking
    against this before granting lets the admin panel refuse loudly instead
    of succeeding with the wrong numbers.

    Disk is handled differently on purpose: the host's real physical disk
    (read below as real_disk_gb, informational only) is currently ~11TB, but
    a chunk of that got eaten by something that overran its expected usage —
    so the real number isn't trustworthy as a selling/allocation ceiling
    anymore. TOTAL_DISK_BUDGET_GB is a deliberately smaller, hand-set cap
    (6TB) that the panel actually enforces for VPS creation/grants,
    independent of whatever the host's real disk happens to report. Every
    individual VPS is still cgrouped/quota'd to its own disk_limit_gb (80GB
    standard) exactly as before — this budget only caps the SUM across all
    VPSes so the panel never promises more than 6TB total, no matter what
    the host's real (currently unreliable) disk size is.

    disk_allocated_gb (from get_allocated_disk_gb()) is REAL usage, not the
    sum of quotas — see that function's docstring. A VPS's 80GB quota is
    just the ceiling it's allowed to grow into; it only counts against this
    budget for what it's actually written.
    """
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
        "real_disk_gb": real_disk_gb,  # informational only — NOT used for any allocation decision
    }


# Deliberately capped well below the host's real physical disk (~11TB) since
# some of that real capacity got eaten by something exceeding its expected
# usage and can no longer be trusted as sellable/allocatable space. This is
# the number the panel actually enforces — see get_allocated_disk_gb() and
# can_allocate_disk() below. To change the advertised/enforced max, edit
# this one constant.
TOTAL_DISK_BUDGET_GB = 6 * 1024  # 6TB


def _quota_gb(inst):
    """Fallback helper: the GB figure from an instance's configured
    devices.root.size (its quota/ceiling, not what it's actually using)."""
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
    """
    Ground-truth disk accounting against the panel-wide TOTAL_DISK_BUDGET_GB,
    based on what every vps- container is ACTUALLY using on disk right now —
    not its configured quota.

    Every VPS still gets a devices.root.size quota (80GB standard) as its own
    ceiling — that's untouched. But a fresh VPS that's used 3GB of its 80GB
    quota should only cost the budget 3GB, not 80GB. Charging the full quota
    up front (the old behavior) is why the budget filled up to 6130/6144GB
    while the physical disk was nowhere near full: 76+ mostly-empty VPSes at
    80GB nominal each eat the whole budget without anyone having written
    that much data.

    LXD reports live per-device usage via instance.state().disk (this is
    what "lxc info <name>" shows as "Disk usage: root: ..."), read directly
    from LXD rather than the DB so it can't drift out of sync with stale or
    deleted rows. If a container's real usage can't be read for some reason
    (storage driver doesn't support usage reporting, container unreachable,
    etc.) we fall back to counting its configured quota for that one
    container — better to overcount a handful of containers than to let the
    budget silently under-enforce.
    """
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


# Physical safety net, independent of the budget above. Once real usage
# (not quotas) is what the budget tracks, the sum of every VPS's *quota*
# can legitimately exceed TOTAL_DISK_BUDGET_GB and even the host's real
# disk — that's the whole point of thin provisioning, and it's fine right
# up until several VPSes actually grow into their quotas at the same time.
# This refuses new allocations once real free space on the host gets low,
# regardless of what the budget math says, so that scenario fails loudly
# (a blocked VPS creation) instead of as an actual full disk on the host.
MIN_FREE_DISK_GB = 100


def can_allocate_disk(additional_gb):
    """
    Returns (allowed: bool, allocated_gb: int, budget_gb: int, reason: str | None).
    reason is only set when allowed is False, and explains WHICH check
    failed — the caller can show it directly instead of a generic message.

    Two independent checks, either one can block:
      1. Budget: real usage across all VPSes + additional_gb must stay
         under TOTAL_DISK_BUDGET_GB.
      2. Physical safety net: real free space on the host must stay above
         MIN_FREE_DISK_GB, no matter what the budget check says.
    """
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
    """container_id here is the LXD instance name (LXD has no separate hash id)."""
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


MAX_TOTAL_VPS = 150  # hard per-node cap — see NODE_FULL_MESSAGE in app.py for what users see


def count_all_vps():
    """
    Ground-truth count of all VPS containers on this node, regardless of status
    (running/suspended/stopped) — counts anything LXD actually knows about with
    the vps- prefix, so it can't drift out of sync with stale DB rows.
    """
    return sum(1 for inst in client.instances.all() if inst.name.startswith("vps-"))


def can_create_vps():
    """Returns (allowed: bool, current_count: int)."""
    current = count_all_vps()
    return current < MAX_TOTAL_VPS, current


def create_vps(username, cpu_limit=1, ram_limit_mb=1024, disk_limit_gb=10, image=IMAGE_ALIAS):
    """
    Create an LXD system container with real cgroup limits. LXD auto-virtualizes
    /proc/meminfo, /proc/cpuinfo etc. for containers with limits.memory/limits.cpu
    set, using its own bundled LXCFS internally — no manual mount setup needed.

    NOTE: security.privileged=true means root inside the container is real root
    on the host (no UID namespace remapping). A container escape here means full
    host compromise. Fine for single-tenant/personal use; risky if other users
    get their own VPS on this same panel.
    """
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
            # privileged+nesting alone can still leave Docker hitting "operation
            # not permitted" on certain syscalls inside the nested container
            # (mknod for device nodes, setxattr for overlayfs metadata). These
            # tell LXD to intercept and allow those specific syscalls safely
            # rather than the kernel blanket-denying them.
            "security.syscalls.intercept.mknod": "true",
            "security.syscalls.intercept.setxattr": "true",
            # Docker's default bridge networking needs these two kernel
            # modules loaded on the host and available to the container.
            # Harmless to request if they're already loaded — just makes
            # sure Docker's iptables/bridge setup inside the VPS doesn't
            # silently fail on hosts where they aren't auto-loaded.
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

        # Retry instead of a single fixed sleep — harmless if the container
        # is ready instantly (as containers usually are), but avoids
        # silently skipping the password set on a slower-booting host.
        _set_root_password_with_retry(inst, password)

        return {
            "container_id": container_name,
            "container_name": container_name,
            "ssh_port": None,  # not applicable — access is via sshx, see create_vps_container()
            "password": password,
            "status": "running",
        }
    except LXDAPIException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def _exec(inst, cmd_list, environment=None):
    """Run a command inside an LXD container. cmd_list is an argv list, not a shell string."""
    return inst.execute(cmd_list, environment=environment or {})


def _set_root_password(inst, password):
    try:
        _exec(inst, ["bash", "-c", f"echo root:{password} | chpasswd"])
    except Exception as e:
        print(f"Failed setting password: {e}")


def _set_root_password_with_retry(inst, password, attempts=15, delay=2):
    """Same as _set_root_password, but retries — a VM's lxd-agent isn't
    ready to accept exec calls the instant the instance shows 'Running',
    unlike a container. Gives up quietly after ~30s and logs it; VPS
    creation still succeeds either way (regen-ssh/reinstall can recover a
    missed password set later)."""
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
    """Parse an LXD limits.memory string ('61440MB', '60GB') back to MB."""
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
    """
    Reads back the cpu/ram/disk this specific container is actually
    configured with — not the standard defaults. Needed so reinstall_vps()
    recreates admin-granted custom-spec VPSes at their real size instead of
    silently downgrading everyone to the standard 4-core/60GB/80GB plan.
    Returns None if the container can't be found/read (caller falls back
    to the standard defaults in that case).
    """
    inst = get_container(container_id)
    if not inst:
        return None
    cpu_raw = inst.config.get("limits.cpu", "4")
    try:
        cpu_cores = int(cpu_raw)
    except Exception:
        cpu_cores = 4
    ram_mb = _parse_mem_mb(inst.config.get("limits.memory", "61440MB")) or 61440
    disk_gb = _quota_gb(inst) or STANDARD_VPS_DISK_GB
    return {"cpu_cores": cpu_cores, "ram_mb": ram_mb, "disk_gb": disk_gb}


def reinstall_vps(container_id, username):
    """
    Wipes a VPS and reinstalls it from scratch: deletes the existing
    container and creates a brand new one with the SAME cpu/ram/disk specs
    it had before (so an admin-granted custom-spec VPS gets reinstalled at
    its real size, not downgraded to the standard plan), then reinstalls
    sshx and opens a fresh terminal session — same path as a brand new
    Create VPS.

    This is destructive: everything on the old disk is gone, and the old
    sshx terminal link stops working immediately. Returns
    (new_container_id, new_ssh_url) on success. Raises on failure — the
    caller should treat that exactly like a failed initial build (status
    'failed', keep the DB row so the user can see what happened).
    """
    specs = get_vps_specs(container_id) or {
        "cpu_cores": 4, "ram_mb": 61440, "disk_gb": STANDARD_VPS_DISK_GB
    }
    # Best-effort delete: if the container's already gone (e.g. an admin
    # deleted it out from under this request) that's fine — recreating it
    # is still the right move rather than aborting the reinstall.
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
    """Alias to match app.py's naming."""
    return delete_vps(container_id)


def regenerate_ssh(container_id):
    """Password + host-key reset variant (kept for parity — not used by app.py, which uses sshx)."""
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
    """
    Ground-truth reconciliation between the DB's idea of a VPS's status and
    what LXD actually reports. Only reconciles the 'running'/'stopped' pair
    — the two states a container can drift into on its own without the
    panel knowing (a host reboot with no container autostart, an OOM kill,
    a crash, or someone using `lxc stop` directly on the host). Without
    this, the DB could say 'running' forever after a container silently
    died, permanently hiding the Start button behind a Stop button that
    always fails.

    Leaves 'queued', 'creating', 'failed', and 'suspended' untouched —
    those are managed explicitly by the app/queue and aren't states LXD
    itself reports.

    Returns the corrected status string (same as db_status if nothing
    drifted, or if the container can't be reached at all — fails closed
    to whatever the DB already believed rather than guessing).
    """
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

def create_vps_container(username, cpu_limit=4, ram_limit_mb=32768, disk_limit_gb=80, image=IMAGE_ALIAS):
    """
    Wrapper matching app.py's expected signature: returns (container_id, session_url).
    Uses sshx for terminal access — installed at container-create time via exec since
    LXD images don't ship it by default. sshx needs no SSH client or keypair on
    either side: it prints a one-time web URL that opens a live terminal in the
    browser (https://sshx.io/s/<id>#<key>), so there's no keygen/entropy step
    like tmate needed.

    Enforces a hard global cap (MAX_TOTAL_VPS) across ALL users on this node —
    once that many containers exist, no more can be created by anyone until
    some are deleted.

    Retries sshx install/session-start up to 3 times each. A silent failure
    here would leave the VPS marked "running" with no way to access it, so
    this raises instead — the caller treats that as a real build failure.
    """
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
    """
    Skips the install script entirely if sshx is already present (e.g. baked
    into the base image — see IMAGE_ALIAS / VPS_IMAGE_ALIAS). Re-running the
    install script on every build is slow and unnecessary once it's there.

    IMPORTANT: sshx's installer drops the binary into $HOME/.local/bin (or
    /usr/local/bin if writable) and relies on the user's shell rc file to add
    that to PATH. `_exec` runs a bare non-login `bash -c` with no HOME set,
    so a plain `command -v sshx` here can report "not found" even after a
    successful install. We explicitly set HOME=/root and check the known
    install locations directly instead of trusting PATH alone. We also
    symlink whatever we find into /usr/local/bin/sshx so every later check
    (including the caller's own retries) hits a stable PATH location instead
    of re-doing this same non-PATH search every time — that search itself
    was a source of intermittent-looking failures under concurrent builds.

    Flakiness this guards against, since "worked before, fails now" almost
    always means something transient rather than a logic bug:
    - curl hitting a transient network blip against sshx.io with no retry/
      timeout of its own (`curl -sSf` gives up on the first failure)
    - apt-get colliding with another concurrent build's dpkg/apt lock when
      installing curl (multiple VPS builds can overlap under load)
    """
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
            return True  # already present — nothing to install

        # Make sure curl exists at all — minimal cloud images sometimes don't ship it.
        curl_check = _exec(inst, ["bash", "-c", "command -v curl"], environment=env)
        if not (curl_check.stdout or "").strip():
            if not _apt_install_with_retry(inst, "curl", env):
                return False

        # --retry/--retry-connrefused/--connect-timeout make the download
        # itself survive a transient network hiccup instead of failing on
        # the first attempt the way a bare `curl -sSf` does.
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
    """Make sure /usr/local/bin/sshx exists and points at the real binary,
    so every future PATH-based lookup (regen, status checks, etc.) is a
    simple `command -v sshx` instead of re-running the non-PATH fallback
    search every single time."""
    if found_path == "/usr/local/bin/sshx":
        return
    try:
        _exec(inst, ["bash", "-c", f"ln -sf '{found_path}' /usr/local/bin/sshx"], environment=env)
    except Exception as e:
        print(f"Could not symlink sshx into /usr/local/bin (non-fatal): {e}")


def _apt_install_with_retry(inst, package, env, attempts=5, wait_seconds=4):
    """
    apt-get/dpkg holds a lock that another concurrent process (e.g. a
    second VPS build's own apt install, or unattended-upgrades) can be
    holding at the exact moment we try to install curl. Rather than fail
    outright on that collision, wait for the lock to clear and retry —
    this is the single most common cause of "worked before, randomly
    fails now" since it depends entirely on timing with other builds.
    """
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
    """
    Starts sshx detached (it normally runs in the foreground for the life of
    the session) and captures the URL it prints on startup from a log file.
    """
    try:
        _exec(inst, ["bash", "-c", "pkill sshx 2>/dev/null; rm -f /tmp/sshx.log; true"])
        # NO_COLOR/TERM=dumb discourage sshx from emitting ANSI color codes
        # in the first place; we still strip any that slip through below,
        # since some builds ignore these hints.
        _exec(inst, ["bash", "-c",
                     "NO_COLOR=1 TERM=dumb nohup sshx > /tmp/sshx.log 2>&1 < /dev/null & disown"])

        url = None
        for _ in range(10):  # sshx connects to the relay almost instantly; poll briefly just in case
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
    """Kills the existing sshx session and starts a fresh one. Note this
    invalidates the previous URL — anyone who had the old link loses access."""
    inst = get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    return _start_sshx_session(inst)


def suspend_vps(container_id):
    """LXD's equivalent of pause: freeze — suspends processes without stopping the container."""
    inst = get_container(container_id)
    if not inst:
        return {"error": "not found"}
    try:
        inst.freeze(wait=True)
    except Exception:
        # not all LXD configs support freeze (needs the freezer cgroup); fall back to stop
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


# --- Port forwarding ---
# Since every container sits on a private LXD bridge, nothing external can
# reach a service inside a VPS (Minecraft, a web server, etc.) without an
# explicit forward. This uses LXD's built-in "proxy" device type: it listens
# on a port on the HOST's public IP and forwards to a port inside the
# container. Only one container can ever claim a given host port at a time,
# since there's one shared public IP for the whole node — so host ports are
# tracked globally across every container, not just per-VPS.

PORT_FORWARD_RANGE = (20000, 29999)


def _all_used_host_ports():
    """Scans every container's proxy devices to find (protocol, port) pairs
    already claimed anywhere on this node — needed because the public IP is
    shared. TCP and UDP are separate port spaces, so 25565/tcp and 25565/udp
    can coexist on two different containers without conflict."""
    used = set()
    for inst in client.instances.all():
        try:
            inst.sync()
            for dev in inst.devices.values():
                if dev.get("type") == "proxy":
                    listen = dev.get("listen", "")  # e.g. "tcp:0.0.0.0:25565"
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
    """
    Adds a proxy device forwarding a host port to a port inside the container.
    Tries preferred_host_port first if given and free; then the same number as
    container_port if free (so e.g. Minecraft's default 25565 stays 25565
    externally too); then the first free port in PORT_FORWARD_RANGE.
    Retries the actual LXD save a few times, since it can transiently fail
    under load the same way container creation can. Returns (host_port,
    device_name). Raises RuntimeError with a clear reason on real failure.
    """
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
    """Alias for monitor.py's naming."""
    return suspend_vps(container_id)


# Rolling cache of last (cpu_ns, timestamp) per container so we can compute a real
# instantaneous CPU% without blocking every call with a sleep. First read for a
# container just seeds the cache and returns 0.0 for cpu_percent.
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
        "cpu_percent": round(cpu_percent, 2),  # real instantaneous %, normalized by core count
        "mem_usage_mb": round(mem_usage / (1024 * 1024), 1),
        "mem_limit_mb": round(mem_limit_bytes / (1024 * 1024), 1),
        "mem_percent": round(mem_percent, 2),
        "uptime_seconds": uptime_seconds,
    }


# Processes that are always safe — never treated as mining evidence, even if
# they show up as CPU-heavy or run from an unusual path. This protects the
# panel's own infra (sshx sessions, sshd, apt upgrades, systemd, etc.) from
# ever being caught by the heuristics below.
_SAFE_PROCESS_WHITELIST = [
    "sshx", "sshd", "systemd", "systemd-journald", "systemd-logind",
    "apt", "apt-get", "dpkg", "unattended-upgrade", "cron", "bash",
    "python3", "app.py", "monitor.py", "vps.py", "gunicorn", "flask",
    "init", "dbus-daemon", "rsyslogd", "networkd-dispatcher",
]

# Known miner binary / process name signatures (xmrig and its common forks/renames,
# other popular CPU miners). Not exhaustive — miners are often renamed to look
# innocuous, so this is a supporting signal, never used alone to suspend.
_MINER_PROCESS_SIGNATURES = [
    "xmrig", "xmr-stak", "cpuminer", "minerd", "cryptonight",
    "nicehash", "ethminer", "t-rex", "lolminer", "phoenixminer",
    "srbminer", "teamredminer", "unmineable", "kdevtmpfsi", "kinsing",
]

# Common mining pool ports (Stratum protocol and known pool defaults).
_MINER_PORTS = ["3333", "4444", "5555", "7777", "8080", "9999", "14444", "45700"]

# Patterns that indicate an actual miner *activation* command was run — i.e. the
# strongest possible evidence, since it shows real intent rather than a
# coincidental process name. This is checked against shell history and the
# full command-line args of running processes.
_MINER_ACTIVATION_PATTERNS = [
    "--donate-level", "--cpu-priority", "-o stratum+tcp", "stratum+tcp://",
    "stratum+ssl://", "--algo=", "-a randomx", "-a rx/0", "--coin=monero",
    "--pool=", "-o pool.", "xmrig -o", "xmrig --url",
]


def _process_is_whitelisted(process_line):
    """True if a ps line's command name matches a known-safe internal process."""
    line_lower = process_line.lower()
    return any(safe in line_lower for safe in _SAFE_PROCESS_WHITELIST)


def _check_command_history(inst):
    """
    Look at recent shell history and currently-running process command lines
    for an actual miner activation pattern (flags/URLs a real miner invocation
    would use). This is the strongest possible signal — far more reliable than
    a process name alone, which can coincidentally match or be spoofed.
    """
    findings = []
    try:
        # Check bash history for common shell users (root, ubuntu) — best effort,
        # history may not be flushed to disk yet for an active session.
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
        # Full command-line args of every running process (ps aux truncates args;
        # this gets the untruncated cmdline for anything currently live).
        result = _exec(inst, ["bash", "-c", "ps -eo args --no-headers"])
        cmdlines = (result.stdout or "").lower()
        for pattern in _MINER_ACTIVATION_PATTERNS:
            if pattern.lower() in cmdlines:
                findings.append(f"activation command in running process: '{pattern}'")
    except Exception:
        pass

    return findings


def check_for_mining(container_id):
    """
    Best-effort check for cryptocurrency mining activity inside a container.
    Deliberately conservative: internal/panel processes are whitelisted and
    can never trigger a positive result, and a positive result requires
    either (a) a verified activation command in history/cmdline, or (b) at
    least two independent weaker signals together (process name + suspicious
    path, or process name + mining port). A single weak signal alone is
    never enough to flag as suspected.

    Returns a dict: {"suspected": bool, "confidence": "high"|"low", "reasons": [...], "raw": {...}}
    """
    inst = get_container(container_id)
    if not inst:
        return {"suspected": False, "confidence": "low", "reasons": ["container not found"], "raw": {}}

    weak_reasons = []
    raw = {}

    # 1. Known miner process names in the process table (excluding whitelisted procs)
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

    # 2. Top CPU-consuming processes running from suspicious paths, excluding whitelisted procs
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

    # 3. Outbound connections on known mining/Stratum ports
    try:
        result = _exec(inst, ["bash", "-c", "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null"])
        conns = result.stdout or ""
        raw["connections"] = conns[:2000]
        for port in _MINER_PORTS:
            if f":{port}" in conns and not _process_is_whitelisted(conns):
                weak_reasons.append(f"outbound connection on common mining port {port}")
    except Exception as e:
        raw["connections_error"] = str(e)

    # 4. Strongest signal: verified activation command in history or live cmdline
    strong_reasons = _check_command_history(inst)
    raw["activation_check"] = strong_reasons

    # Decision logic: a single strong (activation command) match is sufficient on
    # its own. Otherwise, require at least two independent weak signals together
    # before flagging — a lone process-name match or a lone open port is never
    # enough by itself, to avoid false positives against legitimate workloads.
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
            "reasons": weak_reasons,  # kept for logging/visibility even when not acted on
            "raw": raw,
        }


def handle_high_cpu(container_id, threshold=90.0):
    """
    Call this when a container's cpu_percent crosses `threshold`. Only suspends
    on a HIGH-confidence finding (verified miner activation command) — low-
    confidence multi-signal matches are logged but NOT auto-suspended, to make
    absolutely sure no legitimate workload or panel-internal process ever gets
    punished. A legit heavy workload at any CPU% is left running unless mining
    is verifiably confirmed.
    """
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
        # Multiple weak signals but no verified activation command — flag for
        # review, do not auto-suspend.
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
    """Alias for monitor.py: same data, keyed as 'cpu' since that's what watch() checks."""
    s = get_container_stats(container_id)
    return {
        "cpu": s["cpu_percent"],
        "mem_percent": s["mem_percent"],
        "mem_usage_mb": s["mem_usage_mb"],
        "mem_limit_mb": s["mem_limit_mb"],
    }


def build_logs_stream(container_id, follow_seconds=20):
    """
    LXD containers don't have a Docker-style 'docker logs' stream — there's no
    single log endpoint for a whole system container's stdout. Instead this
    tails /var/log/syslog inside the container via exec, once, so the page can
    still reach '[DONE]' right after.
    """
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
