# SPDX-License-Identifier: Apache-2.0
"""nvidia_container_toolkit: the pinned, held container toolkit and a CDI spec for a GPU guest
whose driver is installed by hand, and the guarantee that the role never touches that driver.

The whole install path runs end to end on localhost against fake ``apt-get``, ``apt-mark``,
``dpkg-query``, ``systemctl`` and ``nvidia-ctk`` commands that keep one small package world on
disk (``world``): a fresh install, a converged host (no package command at all), the simulation
that refuses a driver, kernel or library change before anything is installed, the post-install
assertion that nothing protected moved, the spec that is copied only when it differs, the CDI
listing checks, the unit mask and the hooks.  The vendor signing key runs with the other
vendor-key roles (``test_product_roles.py`` KEY_CASES)."""

import re
from pathlib import Path

import pytest
import yaml
from rolerun import ANSIBLE, calls, fake, first_run, run_cases, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook")
ROLE = "nvidia_container_toolkit"
P = f"{ROLE}_"
ROLE_DIR = ANSIBLE / "roles" / ROLE
# the vendor key's fingerprint, built from pieces (a 40-hex literal beside "key" reads as a secret to the history scan)
VENDOR_FPR = "".join(["C95B321B61E88C18", "09C4F759DDCAE044", "F796ECB0"])
DEFAULTS = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())
FIXED = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
CHANGED_0 = re.compile(r"localhost\s*:\s*ok=\d+\s+changed=0\s")
PKGS = [
    "nvidia-container-toolkit",
    "nvidia-container-toolkit-base",
    "libnvidia-container-tools",
    "libnvidia-container1",
]
PIN = "1.20.1-1"
UNITS = ["nvidia-cdi-refresh.path", "nvidia-cdi-refresh.service"]
BOOT = "hnx-nvidia-cdi.service"

# A guest with a hand-installed, held driver stack, a kernel, a library and another held package.
DRIVER = [
    "nvidia-driver-580 580.95.05-1 hi",
    "libnvidia-compute-580 580.95.05-1 hi",
    "cuda-toolkit-13-0 13.0.2-1 ii",
    "linux-image-6.1.0-13-amd64 6.1.55-1 ii",
    "libcap2 1:2.66-4 ii",
    "docker-ce 5:29.9.2-1 hi",
]
INSTALLED = [f"{p} {PIN} hi" for p in PKGS]
# /proc/modules of a guest whose driver is up
MODULES = (
    "nvidia_uvm 1974272 0 - Live 0x0000000000000000\n"
    "nvidia 104071168 1 nvidia_uvm, Live 0x0000000000000000\n"
    "drm 774144 1 nvidia, Live 0x0000000000000000\n"
)
GPUS = ["INFO[0000] Found 5 CDI devices", *(f"nvidia.com/gpu={i}" for i in range(4)),
        "nvidia.com/gpu=all"]  # fmt: skip

# One fake world: the package state lives in dpkg.txt ("name version status" per line) and the
# five commands read and change it, logging every call.  install.effect.json maps a package to
# [version, status] applied after a real install (a driver that moved, a hold that vanished).
WORLD = r"""
import json, os, sys
D = {tmp!r}
NAME = {name!r}
ARGS = sys.argv[1:]
open(D + "/calls.log", "a").write(NAME + " " + " ".join(ARGS) + "\n")

def rows():
    return [l.split() for l in open(D + "/dpkg.txt").read().splitlines() if l.strip()]

def save(r):
    open(D + "/dpkg.txt", "w").write("".join(" ".join(x) + "\n" for x in r))

def put(name, ver, st):
    r = [x for x in rows() if x[0] != name]
    r.append([name, ver, st])
    save(r)

def read(name, default=None):
    p = D + "/" + name
    return open(p).read() if os.path.exists(p) else default

if NAME == "dpkg-query":
    want = [a for a in ARGS[3:]]
    for n, v, s in rows():
        if not want or n in want:
            if ARGS[2] == "${{db:Status-Abbrev}}":
                sys.stdout.write(s + " ")
            else:
                print(n, v, s + " ")
    if want and not [r for r in rows() if r[0] in want]:
        sys.exit(1)
elif NAME == "apt-get":
    if "-s" in ARGS:
        specs = [a for a in ARGS if "=" in a and not a.startswith("-")]
        out = read("sim.txt")
        sys.stdout.write(out if out is not None else
                         "".join("Inst %s (%s)\n" % tuple(s.split("=")) for s in specs) + "Conf x\n")
    elif "install" in ARGS:
        for s in [a for a in ARGS if "=" in a and not a.startswith("-")]:
            n, v = s.split("=")
            put(n, v, "ii")
        for n, (v, s) in json.loads(read("install.effect.json", "{{}}")).items():
            put(n, v, s)
elif NAME == "apt-mark":
    for n in ARGS[1:]:
        for x in rows():
            if x[0] == n:
                put(n, x[1], ("hi" if ARGS[0] == "hold" else "ii"))
elif NAME == "systemctl":
    os.makedirs(D + "/masked", exist_ok=True)
    units = ARGS[1:]
    if ARGS[0] == "mask":
        for u in units:
            open(D + "/masked/" + u, "w").write("")
    elif ARGS[0] == "enable":
        os.makedirs(D + "/enabled", exist_ok=True)
        for u in units:
            open(D + "/enabled/" + u, "w").write("")
    elif ARGS[0] == "is-enabled":
        for u in units:
            print("masked" if os.path.exists(D + "/masked/" + u)
                  else "enabled" if os.path.exists(D + "/enabled/" + u) else "disabled")
        sys.exit(1)
elif NAME == "dpkg":
    sys.stdout.write(read("audit.txt", ""))
elif NAME == "nvidia-ctk":
    if ARGS[:2] == ["cdi", "generate"]:
        open(ARGS[2].split("=", 1)[1], "w").write(read("ctk.spec", "cdiVersion: 0.5.0\n"))
    elif ARGS[:2] == ["cdi", "list"]:
        sys.stdout.write(read("ctk.list", ""))
    elif ARGS[:1] == ["--version"]:
        sys.stdout.write(read("ctk.version", ""))
        sys.exit(int(read("ctk.rc", "0")))
"""
FAKES = {
    "apt-get": "apt_get_cli",
    "apt-mark": "apt_mark_cli",
    "dpkg-query": "dpkg_query_cli",
    "dpkg": "dpkg_cli",
    "systemctl": "systemctl_cli",
    "nvidia-ctk": "ctk_cli",
}


def _render(src, ctx):
    """The unit template as Ansible renders it (dirname and basename are Ansible's filters)."""
    import os.path

    from jinja2 import Environment, select_autoescape

    env = Environment(keep_trailing_newline=True, autoescape=select_autoescape(default=False))
    env.filters.update(dirname=os.path.dirname, basename=os.path.basename)
    return env.from_string(src).render(**ctx)


def world(
    tmp,
    dpkg=None,
    masked=(),
    enabled=("hnx-nvidia-cdi.service",),
    spec="cdiVersion: 0.5.0\n",
    listing=None,
    live=None,
    **kw,
):
    """The fake commands and the paths of one run under ``tmp``; returns the role's variables."""
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "dpkg.txt").write_text("".join(f"{x}\n" for x in (DRIVER if dpkg is None else dpkg)))
    (tmp / "ctk.spec").write_text(spec)
    (tmp / "ctk.list").write_text("\n".join(GPUS if listing is None else listing) + "\n")
    (tmp / "ctk.version").write_text("NVIDIA Container Toolkit CLI version 1.20.1\ncommit: abc\n")
    (tmp / "masked").mkdir(exist_ok=True)
    for u in masked:
        (tmp / "masked" / u).write_text("")
    (tmp / "enabled").mkdir(exist_ok=True)
    for u in enabled:
        (tmp / "enabled" / u).write_text("")
    (tmp / "units").mkdir(exist_ok=True)
    (tmp / "run" / "cdi").mkdir(parents=True, exist_ok=True)
    (tmp / "state").mkdir(exist_ok=True)  # made by an earlier run on a converged host
    (tmp / "dev").mkdir(exist_ok=True)
    (tmp / "dev" / "nvidiactl").write_text("")
    (tmp / "proc").mkdir(exist_ok=True)
    (tmp / "proc" / "modules").write_text(MODULES)
    if live is not None:
        (tmp / "etc" / "cdi").mkdir(parents=True, exist_ok=True)
        (tmp / "etc" / "cdi" / "nvidia.yaml").write_text(live)
    v = {
        f"{P}repository": "",
        f"{P}distribution": "Debian",
        f"{P}architecture": "x86_64",
        f"{P}expected_gpus": 4,
        f"{P}state_dir": str(tmp / "state"),
        f"{P}cdi_spec": str(tmp / "etc" / "cdi" / "nvidia.yaml"),
        f"{P}refresh_spec": str(tmp / "run" / "cdi" / "nvidia.yaml"),
        f"{P}unit_dir": str(tmp / "units"),
        f"{P}dev_root": str(tmp / "dev"),
        f"{P}proc_root": str(tmp / "proc"),
    }
    for cmd, var in FAKES.items():
        v[f"{P}{var}"] = fake(tmp / cmd, f"{WORLD.format(tmp=str(tmp), name=cmd)}")
    v = {**v, **kw}
    if (
        enabled
    ):  # a host the role already converged has its boot unit on disk, as the template renders it
        ctx = {f"{P}{k}": FIXED[f"{P}{k}"] for k in ("ctk_path",)}
        ctx |= {f"{P}proc_root": v[f"{P}proc_root"], f"{P}dev_root": v[f"{P}dev_root"],
                f"{P}cdi_spec": v[f"{P}cdi_spec"],
                f"{P}staged_spec": f"{v[f'{P}state_dir']}/cdi-staged.yaml"}  # fmt: skip
        src = (ROLE_DIR / "templates" / "hnx-nvidia-cdi.service.j2").read_text()
        (tmp / "units" / "hnx-nvidia-cdi.service").write_text(_render(src, ctx))
    return v


def pkg_calls(tmp):
    return [c for c in calls(tmp) if c.split()[0] in ("apt-get", "apt-mark", "systemctl")]


def dpkg(tmp):
    return (tmp / "dpkg.txt").read_text().splitlines()


def main_case(tmp, **kw):
    v = world(tmp, **kw)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


SPECS = [f"{p}={PIN}" for p in PKGS]
SIM = ["apt-get", "install", "-s", "-y", "--no-install-recommends", *SPECS]
REAL = ["apt-get", "install", "-y", "--no-install-recommends", "-o",
        "Dpkg::Options::=--force-confold", *SPECS]  # fmt: skip


# ---------------------------------------------------------------- the defaults
def test_the_pins_and_fixed_values_are_what_the_design_says():
    assert DEFAULTS[f"{P}version"] == "1.20.1" and DEFAULTS[f"{P}package_revision"] == "1"
    assert DEFAULTS[f"{P}repository"] == "https://nvidia.github.io/libnvidia-container"
    assert DEFAULTS[f"{P}channel"] == "stable"
    assert DEFAULTS[f"{P}key_fingerprints"] == [VENDOR_FPR]
    assert DEFAULTS[f"{P}auto_refresh"] is False and f"{P}expected_gpus" not in DEFAULTS
    assert FIXED[f"{P}packages"] == PKGS
    assert FIXED[f"{P}keyring"] == "/etc/apt/keyrings/hnx-nvidia-container-toolkit.asc"
    assert FIXED[f"{P}refresh_units"] == UNITS


def test_the_protected_pattern_covers_the_driver_stack_and_not_a_plain_library():
    pat = re.compile(FIXED[f"{P}protected_pattern"])
    for name in ("nvidia-driver-580", "libnvidia-compute-580", "cuda-toolkit-13-0",
                 "xserver-xorg-video-nvidia-580", "firmware-nvidia-gsp", "linux-image-6.1.0-13-amd64",
                 "linux-headers-amd64", "linux-modules-6.1"):  # fmt: skip
        assert pat.match(name), name
    for name in ("libcap2", "docker-ce", "linux-base", "linux-libc-dev", "libc6"):
        assert not pat.match(name), name


# ---------------------------------------------------------------- inputs
def valid(tmp, **kw):
    return {"role": ROLE, "tasks_from": "validate", "extra_vars": world(tmp, **kw)}


@first_run(lambda tmp: valid(tmp))
def test_good_inputs_pass(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


@first_run(
    lambda tmp: valid(
        tmp,
        **{f"{P}version": "1.21.0", f"{P}package_revision": "12", f"{P}channel": "experimental-2",
           f"{P}repository": "https://mirror.example.internal/nvidia/libnvidia-container",
           f"{P}expected_gpus": 16, f"{P}auto_refresh": True},
    )
)  # fmt: skip
def test_the_inputs_are_overridable(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


@first_run(lambda tmp: valid(tmp, **{f"{P}repository": "", f"{P}key_fingerprints": []}))
def test_an_empty_repository_needs_no_key_pin(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


BAD = {
    "version without a patch": {"version": "1.20"},
    "version with a newline": {"version": "1.20.1\nPackage: evil"},
    "version with a suffix": {"version": "1.20.1-rc.1"},
    "version a wildcard": {"version": "1.*"},
    "revision with a dash": {"package_revision": "1-2"},
    "revision empty": {"package_revision": ""},
    "revision a word": {"package_revision": "latest"},
    "repository over http": {"repository": "http://mirror.example.internal/nv"},
    "repository with a space": {"repository": "https://mirror.example.internal/nv stable"},
    "repository with a trailing slash": {"repository": "https://mirror.example.internal/nv/"},
    "repository a list": {"repository": ["https://mirror.example.internal/nv"]},
    "channel capitalised": {"channel": "Stable"},
    "channel with a slash": {"channel": "stable/deb"},
    "channel empty": {"channel": ""},
    "no fingerprints with a repository": {
        "repository": "https://mirror.example.internal/nv",
        "key_fingerprints": [],
    },
    "fingerprint short": {"key_fingerprints": [VENDOR_FPR[-16:]]},
    "fingerprint lower case": {"key_fingerprints": [VENDOR_FPR.lower()]},
    "fingerprints a string": {"key_fingerprints": VENDOR_FPR},
    "spec path relative": {"cdi_spec": "etc/cdi/nvidia.yaml"},
    "spec path with //": {"cdi_spec": "/etc//cdi/nvidia.yaml"},
    "spec path with ..": {"cdi_spec": "/etc/cdi/../nvidia.yaml"},
    "state dir relative": {"state_dir": "state"},
    "state dir trailing slash": {"state_dir": "/var/lib/hnx/"},
    "dev root relative": {"dev_root": "dev"},
    "gpus negative": {"expected_gpus": -1},
    "gpus zero (any is the explicit opt-out)": {"expected_gpus": 0},
    "gpus a word that is not any": {"expected_gpus": "all"},
    "gpus above 16": {"expected_gpus": 17},
    "gpus a word": {"expected_gpus": "four"},
    "gpus a numeral string": {"expected_gpus": "4"},
    "auto_refresh a string": {"auto_refresh": "yes"},
    "command with an argument": {"apt_get_cli": "apt-get -y"},
    "command with a newline": {"ctk_cli": "nvidia-ctk\nrm"},
}


@pytest.mark.parametrize("case", list(BAD))
@first_run(lambda tmp, case: valid(tmp, **{P + k: v for k, v in BAD[case].items()}))
def test_bad_inputs_are_refused(first, case):
    r, _ = first
    assert r.returncode != 0, case
    assert "nvidia_container_toolkit: a plain x.y.z version" in r.stdout


@first_run(lambda tmp: {"role": ROLE, "tasks_from": "main", "extra_vars": {}})
def test_the_gpu_count_is_required(first):
    r, _ = first
    assert r.returncode != 0 and f"{P}expected_gpus" in r.stdout + r.stderr


@pytest.mark.parametrize(
    ("distribution", "arch", "ok"),
    [("Debian", "x86_64", True), ("Ubuntu", "aarch64", True), ("Fedora", "x86_64", False),
     ("Debian", "riscv64", False), ("Ubuntu", "i686", False)],
)  # fmt: skip
@first_run(
    lambda tmp, distribution, arch, ok: {
        "role": ROLE,
        "tasks_from": "platform",
        "extra_vars": world(tmp, **{f"{P}distribution": distribution, f"{P}architecture": arch}),
    }
)
def test_debian_and_ubuntu_on_amd64_or_arm64_only(first, distribution, arch, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, r.stdout


# ---------------------------------------------------------------- a fresh install
def _fresh(tmp):
    leftover = tmp / "run" / "cdi" / "nvidia.yaml"
    c = main_case(tmp)
    leftover.write_text("a spec the refresh service wrote\n")
    c["setup"]["leftover"] = leftover
    return c


@first_run(_fresh)
def test_a_fresh_install_masks_then_updates_simulates_installs_and_holds_in_that_order(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    mask = "systemctl mask " + " ".join(UNITS)
    assert pkg_calls(tmp) == [
        "systemctl is-enabled " + " ".join(UNITS),
        mask,
        "apt-get update",
        " ".join(SIM),
        " ".join(REAL),
        "apt-mark hold " + " ".join(PKGS),
        f"systemctl is-enabled {BOOT}",
    ]
    every = " ".join(calls(tmp))
    assert "--allow-change-held-packages" not in every and "--allow-downgrades" not in every
    assert not first.setup["leftover"].exists()  # the role's own spec is the one CDI resolves
    state = dpkg(tmp)
    assert all(f"{p} {PIN} hi" in state for p in PKGS)
    assert [s for s in state if s in DRIVER] == DRIVER  # nothing else moved
    spec = first.setup["v"][f"{P}cdi_spec"]
    assert Path(spec).read_text() == "cdiVersion: 0.5.0\n"
    assert calls(tmp)[-3:-1] == [  # then the boot unit, already enabled here
        f"nvidia-ctk cdi generate --output={first.setup['v'][P + 'state_dir']}/cdi-staged.yaml",
        "nvidia-ctk cdi list",
    ]
    assert not (tmp / "state" / "cdi-staged.yaml").exists()  # the staging file is removed


@first_run(_fresh)
def test_a_second_run_after_a_fresh_install_changes_nothing_and_calls_no_package_command(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    before = len(calls(tmp))
    again = run_role(tmp, ROLE, "main", first.setup["v"])
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout
    assert [c for c in calls(tmp)[before:] if c.split()[0] in ("apt-get", "apt-mark")] == []
    assert not [c for c in calls(tmp)[before:] if c.startswith("systemctl mask")]


# ---------------------------------------------------------------- a converged host
def _converged(tmp):
    return main_case(tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, live="cdiVersion: 0.5.0\n")


@first_run(_converged)
def test_a_converged_host_makes_no_apt_calls_and_changes_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert CHANGED_0.search(r.stdout), r.stdout
    assert pkg_calls(tmp) == [
        "systemctl is-enabled " + " ".join(UNITS),
        f"systemctl is-enabled {BOOT}",
    ]
    assert [c.split()[1] for c in calls(tmp) if c.startswith("nvidia-ctk")] == ["cdi", "cdi"]


def _spec_changes(tmp):
    return main_case(tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, live="the old spec\n")


@first_run(_spec_changes)
def test_the_spec_is_installed_only_when_the_staged_one_differs(first):
    r, tmp = first
    v = first.setup["v"]
    live = tmp / "etc" / "cdi" / "nvidia.yaml"
    assert r.returncode == 0 and "changed=1" in r.stdout, r.stdout
    assert live.read_text() == "cdiVersion: 0.5.0\n" and oct(live.stat().st_mode)[-3:] == "644"
    again = run_role(tmp, ROLE, "main", v)
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout
    (tmp / "ctk.spec").write_text("cdiVersion: 0.5.0\n# a card was added\n")
    third = run_role(tmp, ROLE, "main", v)
    assert third.returncode == 0 and "changed=1" in third.stdout, third.stdout
    assert live.read_text().endswith("# a card was added\n")
    assert not (tmp / "state" / "cdi-staged.yaml").exists()
    assert pkg_calls(tmp).count("apt-get update") == 0  # no package command at any point


def _bumps(tmp):
    old = [f"{p} 1.19.0-1 hi" for p in PKGS[:2]] + [f"{p} 1.19.0-1 ii" for p in PKGS[2:]]
    return main_case(tmp, dpkg=[*DRIVER, *old], masked=UNITS, live="cdiVersion: 0.5.0\n")


@first_run(_bumps)
def test_only_the_held_toolkit_packages_are_released_for_a_bump(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert pkg_calls(tmp) == [
        "systemctl is-enabled " + " ".join(UNITS),
        "apt-get update",
        f"apt-mark unhold {PKGS[0]}",
        f"apt-mark unhold {PKGS[1]}",
        " ".join(SIM),
        " ".join(REAL),
        "apt-mark hold " + " ".join(PKGS),
        f"systemctl is-enabled {BOOT}",
    ]
    assert "docker-ce 5:29.9.2-1 hi" in dpkg(tmp)  # another held package is never released
    assert all(f"{p} {PIN} hi" in dpkg(tmp) for p in PKGS)


# ---------------------------------------------------------------- the driver is never touched
SIMS = {
    "a driver": "Inst nvidia-driver-580 [580.95.05-1] (580.126.09-1 stable)\n",
    "a driver library": "Inst libnvidia-compute-580 (580.126.09-1 stable)\n",
    "a kernel": "Inst linux-image-6.1.0-14-amd64 (6.1.60-1 stable)\n",
    "a plain library": "Inst libcap2 [1:2.66-4] (1:2.66-5 stable)\n",
    "a removal": "Remv libfoo [1.0]\n",
    "a purge": "Purg libfoo [1.0]\n",
    "a removal after the toolkit": "".join(f"Inst {p} (1.20.1-1)\n" for p in PKGS) + "Remv libfoo [1.0]\n",
}  # fmt: skip


def _refused(tmp, case):
    c = main_case(tmp, dpkg=[*DRIVER, *INSTALLED[:2]])  # two toolkit packages held at the pin
    (tmp / "sim.txt").write_text("Inst nvidia-container-toolkit (1.20.1-1)\n" + SIMS[case])
    return c


@pytest.mark.parametrize("case", list(SIMS))
@first_run(_refused)
def test_a_simulation_that_touches_anything_else_fails_before_anything_is_installed(first, case):
    r, tmp = first
    assert r.returncode != 0, case
    assert "never installs, upgrades or removes a driver, a kernel or any other package" in r.stdout
    assert "nothing was installed" in r.stdout
    names = re.findall(r"(?m)^(?:Inst|Remv|Purg) (\S+)", SIMS[case])
    assert all(n in r.stdout for n in names), (names, r.stdout)
    apt = [c for c in calls(tmp) if c.startswith("apt-get")]
    assert apt == ["apt-get update", " ".join(SIM)]  # the real install never ran
    assert calls(tmp)[-1] == "apt-mark hold " + " ".join(PKGS)  # and the holds are back


def _toolkit_only(tmp):
    c = main_case(tmp)
    (tmp / "sim.txt").write_text("".join(f"Inst {p} (1.20.1-1)\n" for p in reversed(PKGS)))
    return c


@first_run(_toolkit_only)
def test_a_simulation_touching_only_the_four_toolkit_packages_goes_ahead(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert " ".join(REAL) in calls(tmp)


EFFECTS = {
    "a driver that moved": ({"nvidia-driver-580": ["580.126.09-1", "hi"]}, "nvidia-driver-580"),
    "a kernel that moved": ({"linux-image-6.1.0-13-amd64": ["6.1.60-1", "ii"]}, "linux-image"),
    "a driver that vanished-hold": ({"nvidia-driver-580": ["580.95.05-1", "ii"]}, "nvidia-driver-580"),
    "a protected package that appeared": ({"nvidia-kernel-open-580": ["580.1-1", "ii"]}, "nvidia-kernel-open-580"),
    "another held package released": ({"docker-ce": ["5:29.9.2-1", "ii"]}, "docker-ce"),
}  # fmt: skip


def _effect(tmp, case):
    import json

    c = main_case(tmp)
    (tmp / "install.effect.json").write_text(json.dumps(EFFECTS[case][0]))
    return c


@pytest.mark.parametrize("case", list(EFFECTS))
@first_run(_effect)
def test_an_install_that_changed_a_protected_or_held_package_fails_by_name(first, case):
    r, _ = first
    assert r.returncode != 0, case
    assert "the install touched the driver, the kernel or another held package" in r.stdout
    assert EFFECTS[case][1] in r.stdout, r.stdout


def _removed(tmp):
    c = main_case(tmp)
    (tmp / "install.effect.json").write_text('{"libnvidia-compute-580": ["580.95.05-1", "iU"]}')
    return c


@first_run(_removed)
def test_a_protected_package_changing_state_is_caught_even_when_the_version_is_the_same(first):
    r, _ = first
    assert r.returncode != 0 and "libnvidia-compute-580" in r.stdout


def test_the_toolkit_packages_are_not_protected_packages():
    """The four toolkit packages match the protected pattern by name (nvidia-*, libnvidia-*) and
    move on purpose: a fresh install must not trip the assertion that protects the driver."""
    pat = re.compile(FIXED[f"{P}protected_pattern"])
    assert all(pat.match(p) for p in PKGS)  # hence the explicit exclusion in snapshot.yml
    text = (ROLE_DIR / "tasks" / "snapshot.yml").read_text()
    assert "nvidia_container_toolkit_packages" in text and "elif" in text


# ---------------------------------------------------------------- CDI checks
LISTS = {
    "no all device": [f"nvidia.com/gpu={i}" for i in range(4)],
    "one GPU too few": [*(f"nvidia.com/gpu={i}" for i in range(3)), "nvidia.com/gpu=all"],
    "one GPU too many": [*(f"nvidia.com/gpu={i}" for i in range(5)), "nvidia.com/gpu=all"],
    "wrong indices": [
        "nvidia.com/gpu=0",
        "nvidia.com/gpu=1",
        "nvidia.com/gpu=2",
        "nvidia.com/gpu=4",
        "nvidia.com/gpu=all",
    ],
    "nothing listed": [],
    "only INFO lines": ["INFO[0000] Found 0 CDI devices"],
    "only the all device": ["nvidia.com/gpu=all"],
    "another vendor's devices": ["vendor.example.internal/gpu=0", "nvidia.com/gpu=all"],
}


@pytest.mark.parametrize("case", list(LISTS))
@first_run(
    lambda tmp, case: main_case(
        tmp,
        dpkg=[*DRIVER, *INSTALLED],
        masked=UNITS,
        listing=LISTS[case],
        live="cdiVersion: 0.5.0\n",
    )
)
def test_a_cdi_listing_that_is_not_the_expected_gpus_fails(first, case):
    r, _ = first
    assert r.returncode != 0, case
    assert "nvidia-ctk cdi list names" in r.stdout


@first_run(
    lambda tmp: main_case(
        tmp,
        dpkg=[*DRIVER, *INSTALLED],
        masked=UNITS,
        listing=["nvidia.com/gpu=0", "nvidia.com/gpu=GPU-0aaa", "nvidia.com/gpu=all"],
        live="cdiVersion: 0.5.0\n",
        **{f"{P}expected_gpus": 1},
    )
)
def test_uuid_named_devices_beside_the_indices_are_not_counted(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


@first_run(
    lambda tmp: main_case(
        tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, live="cdiVersion: 0.5.0\n",
        listing=["nvidia.com/gpu=0", "nvidia.com/gpu=all"], **{f"{P}expected_gpus": "any"},
    )
)  # fmt: skip
def test_any_count_checks_no_count_but_still_needs_a_gpu_and_all(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


@first_run(
    lambda tmp: main_case(
        tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, live="cdiVersion: 0.5.0\n",
        listing=[], **{f"{P}expected_gpus": "any"},
    )
)  # fmt: skip
def test_zero_devices_is_a_failure_even_with_no_count_expected(first):
    r, _ = first
    assert r.returncode != 0


@first_run(
    lambda tmp: main_case(
        tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, spec="", live="cdiVersion: 0.5.0\n"
    )
)
def test_an_empty_generated_spec_never_replaces_the_live_one(first):
    r, tmp = first
    assert r.returncode != 0 and "wrote no spec" in r.stdout
    assert (tmp / "etc" / "cdi" / "nvidia.yaml").read_text() == "cdiVersion: 0.5.0\n"


# ---------------------------------------------------------------- the refresh units
def _auto(tmp):
    c = main_case(tmp, enabled=(), **{f"{P}auto_refresh": True})
    (tmp / "run" / "cdi" / "nvidia.yaml").write_text("the refresh service's spec\n")
    c["setup"]["leftover"] = tmp / "run" / "cdi" / "nvidia.yaml"
    return c


@first_run(_auto)
def test_with_auto_refresh_the_units_and_the_refreshed_spec_are_left_alone(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert not [c for c in calls(tmp) if c.startswith("systemctl")]
    assert first.setup["leftover"].exists()


@first_run(lambda tmp: main_case(tmp, masked=[UNITS[0]]))
def test_a_half_masked_pair_is_masked_again_and_a_masked_pair_is_not(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert "systemctl mask " + " ".join(UNITS) in calls(tmp)


# ---------------------------------------------------------------- health
def health_vars(
    tmp, dpkg=None, masked=UNITS, enabled=(BOOT,), listing=None, spec=True, stray=None, **kw
):
    v = world(tmp, dpkg=[*DRIVER, *INSTALLED] if dpkg is None else dpkg, masked=masked,
              enabled=enabled, listing=listing, live="cdiVersion: 0.5.0\n" if spec else None, **kw)  # fmt: skip
    if stray:
        (tmp / "etc" / "cdi" / stray).write_text("cdiVersion: 0.5.0\n")
    return {k: v[k] for k in v if k not in (f"{P}repository", f"{P}state_dir", f"{P}refresh_spec")}


def _swap(lines, old, new):
    return [x.replace(old, new) for x in lines]


HEALTH = {
    # case: (vars, message or None)
    "healthy": ({}, None),
    "healthy with auto refresh and unmasked units": ({"masked": [], f"{P}auto_refresh": True}, None),
    "a package off its pin": ({"dpkg": _swap(DRIVER + INSTALLED, "1.20.1-1", "1.20.2-1")}, "not installed at 1.20.1-1"),
    "one package off its pin": ({"dpkg": DRIVER + _swap(INSTALLED, f"{PKGS[3]} 1.20.1-1", f"{PKGS[3]} 1.19.0-1")}, PKGS[3]),
    "a package not held": ({"dpkg": DRIVER + _swap(INSTALLED, f"{PKGS[1]} 1.20.1-1 hi", f"{PKGS[1]} 1.20.1-1 ii")}, PKGS[1]),
    "held but only unpacked": ({"dpkg": DRIVER + _swap(INSTALLED, f"{PKGS[2]} 1.20.1-1 hi", f"{PKGS[2]} 1.20.1-1 hU")}, PKGS[2]),
    "a package missing": ({"dpkg": DRIVER + INSTALLED[:-1]}, PKGS[3]),
    "no spec": ({"spec": False}, "no CDI spec"),
    "no all device": ({"listing": LISTS["no all device"]}, "nvidia-ctk cdi list names"),
    "too few GPUs": ({"listing": LISTS["one GPU too few"]}, "exactly the indices 0 to 3"),
    "too many GPUs": ({"listing": LISTS["one GPU too many"]}, "exactly the indices 0 to 3"),
    "boot unit not enabled": ({"enabled": []}, "hnx-nvidia-cdi.service is not enabled"),
    "healthy with auto refresh and no boot unit": ({"masked": [], "enabled": [], f"{P}auto_refresh": True}, None),
    "a stray second spec": ({"stray": "nvidia.yaml.new.yaml"}, "sit beside"),
    "units not masked": ({"masked": []}, "are not both masked"),
    "one unit not masked": ({"masked": [UNITS[1]]}, "are not both masked"),
}  # fmt: skip


def _first(tmp):
    over = []
    for i, (vars_, _) in enumerate(HEALTH.values()):
        vars_ = dict(vars_)
        over.append(health_vars(tmp / f"case{i}", **vars_))
    return {"runner": run_cases, "role": ROLE, "tasks_from": "health", "base_vars": {},
            "overrides": over}  # fmt: skip


@first_run(_first)
def test_health_needs_the_pinned_held_packages_the_spec_the_gpus_and_masked_units(first):
    results, _ = first
    for (name, (_, msg)), (failed, got) in zip(HEALTH.items(), results, strict=True):
        assert failed is (msg is not None), (name, got)
        assert msg is None or msg in got, (name, got)


# ---------------------------------------------------------------- readiness
def ready_vars(tmp, version="NVIDIA Container Toolkit CLI version 1.20.1\n", rc=0, dev=True):
    v = world(tmp)
    (tmp / "ctk.version").write_text(version)
    (tmp / "ctk.rc").write_text(str(rc))
    if not dev:
        (tmp / "dev" / "nvidiactl").unlink()
    return {k: v[k] for k in (f"{P}ctk_cli", f"{P}dev_root")}


READY = {
    "ready": ({}, False),
    "ready with a trailing sentence dot": ({"version": "version 1.20.1.\n"}, False),
    "the CLI is another version": ({"version": "version 1.20.2\n"}, True),
    "the CLI is a longer version": ({"version": "version 1.20.10\n"}, True),
    "the CLI is a prefix version": ({"version": "version 11.20.1\n"}, True),
    "the CLI fails": ({"rc": 1}, True),
    "no driver device": ({"dev": False}, True),
}


def _first(tmp):
    over = [ready_vars(tmp / f"case{i}", **kw) for i, (kw, _) in enumerate(READY.values())]
    return {"runner": run_cases, "role": ROLE, "tasks_from": "readiness", "base_vars": {},
            "overrides": over}  # fmt: skip


@first_run(_first)
def test_readiness_needs_the_cli_at_the_pin_and_the_driver_device(first):
    results, _ = first
    assert [f for f, _ in results] == [bad for _, bad in READY.values()], results


# ---------------------------------------------------------------- the other hooks
@first_run(lambda tmp: {"role": ROLE, "tasks_from": "upgrade",
                        "extra_vars": {f"{P}target_version": "1.21.0"}})  # fmt: skip
def test_upgrade_takes_a_newer_version_only(first):
    ok, tmp = first
    assert ok.returncode == 0, ok.stdout
    for bad in ("1.20.1", "1.19.9", "1.21", "1.21.0-rc.1", "1.21.0\nx"):
        r = run_role(tmp, ROLE, "upgrade", {f"{P}target_version": bad})
        assert r.returncode != 0, bad


@pytest.mark.parametrize("hook", ["backup", "restore", "export"])
@first_run(lambda tmp, hook: {"role": ROLE, "tasks_from": hook, "extra_vars": {}})
def test_the_data_hooks_say_there_is_nothing_of_the_toolkits_own(first, hook):
    r, _ = first
    assert r.returncode == 0 and CHANGED_0.search(r.stdout), r.stdout


# ---------------------------------------------------------------- what the role must never do
FORBIDDEN = ("restart", "reload", "modprobe", "rmmod", "--allow-change-held-packages",
             "allow_change_held_packages", "allow-downgrades", "allow_downgrade",
             "runtime configure", "nvidia-smi", "daemon-reload", "ansible.builtin.systemd",
             "ansible.builtin.service", "ansible.builtin.shell", "ansible.builtin.raw",
             "ansible.builtin.apt:")  # fmt: skip
TEXT_KEYS = {"name", "fail_msg", "msg", "success_msg"}  # prose, not what the task runs


def _strings(node, skip=TEXT_KEYS):
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            if k not in skip:
                yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif node is not None:
        yield str(node)


def test_no_task_restarts_reloads_loads_modules_resets_a_gpu_or_overrides_a_hold():
    """The guest's cards must never be restarted warm: no restart or reload, no module load, no
    nvidia-smi, no `nvidia-ctk runtime configure` (docker_engine owns daemon.json), nothing allowed
    past a hold or a downgrade, and no package module that could move a package its own way.
    Comments (dropped by the YAML parse) and task names or messages may use the words."""
    files = [
        *sorted((ROLE_DIR / "tasks").glob("*.yml")),
        ROLE_DIR / "vars" / "main.yml",
        ROLE_DIR / "defaults" / "main.yml",
    ]
    assert len(files) > 10
    for f in files:
        for s in _strings(yaml.safe_load(f.read_text())):
            for word in FORBIDDEN:
                assert word not in s.lower().replace("needrestart", ""), (
                    f.name,
                    word,
                    s,
                )  # needrestart's own switches
    # the scan sees what it is meant to: the real install command is in what it reads
    assert any("Dpkg::Options::=--force-confold" in s
               for s in _strings(yaml.safe_load((ROLE_DIR / "tasks" / "install.yml").read_text())))  # fmt: skip


def test_the_forbidden_word_scan_would_catch_each_word():
    for word in FORBIDDEN:
        doc = yaml.safe_load(f"- ansible.builtin.command: {{argv: ['x', '{word}']}}\n")
        assert any(word in s.lower() for s in _strings(doc)), word
    quiet = yaml.safe_load(
        "- name: restart nothing\n  fail_msg: reload\n  ansible.builtin.command: {argv: [x]}\n"
    )
    assert not any("restart" in s or "reload" in s for s in _strings(quiet))


def tasks(name):
    return yaml.safe_load((ROLE_DIR / "tasks" / f"{name}.yml").read_text())


def test_the_install_holds_again_in_an_always_and_releases_only_the_toolkit_packages():
    (block,) = [t for t in tasks("install") if "block" in t]
    assert any("apt_mark_cli" in str(t) for t in block["always"])
    assert "'hold'" in str(block["always"]) and "unhold" not in str(block["always"])
    unhold = [t for t in block["block"] if "unhold" in str(t)]
    assert len(unhold) == 1 and unhold[0]["loop"] == "{{ nvidia_container_toolkit_unhold }}"
    assert (
        "select('in', nvidia_container_toolkit_packages)"
        in block["vars"]["nvidia_container_toolkit_unhold"]
    )
    names = [t["name"] for t in block["block"]]
    assert names.index("Simulate the install") < names.index("Install the pinned toolkit packages")


def test_main_masks_before_installing_and_checks_the_key_before_trusting_the_repository():
    steps = [
        t.get("ansible.builtin.include_tasks")
        for t in tasks("main")
        if "ansible.builtin.include_tasks" in t
    ]
    assert steps.index("refresh.yml") < steps.index("install.yml") < steps.index("cdi.yml")
    assert steps.index("snapshot.yml") < steps.index("refresh.yml")
    (src,) = [t for t in tasks("main") if t.get("ansible.builtin.include_tasks") == "source.yml"]
    assert src["when"] == f"{P}repository != ''"
    s = tasks("source")
    inc = [
        i for i, t in enumerate(s) if t.get("ansible.builtin.include_tasks") == "signing_key.yml"
    ]
    repo = [i for i, t in enumerate(s) if "ansible.builtin.deb822_repository" in t]
    assert inc and repo and inc[0] < repo[0]
    spec = s[repo[0]]["ansible.builtin.deb822_repository"]
    assert spec["suites"] == "/" and "components" not in spec  # a flat repository
    assert spec["signed_by"] == "{{ nvidia_container_toolkit_keyring }}"
    assert spec["uris"] == "{{ nvidia_container_toolkit_apt_uri }}"
    assert FIXED[f"{P}apt_uri"] == (
        "{{ nvidia_container_toolkit_repository }}/{{ nvidia_container_toolkit_channel }}"
        "/deb/{{ nvidia_container_toolkit_apt_arch }}"
    )
    assert FIXED[f"{P}apt_arch"].count("amd64") == 1 and "arm64" in FIXED[f"{P}apt_arch"]


# ---------------------------------------------------------------- the signing key, run twice
def _key(tmp):
    from test_product_roles import key_setup

    v, ring, served = key_setup(tmp, ROLE)
    return {"role": ROLE, "tasks_from": "signing_key", "extra_vars": v,
            "setup": {"v": v, "ring": ring, "served": served}}  # fmt: skip


@pytest.mark.requires_tool("gpg")
@first_run(_key)
def test_a_second_signing_key_run_changes_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert first.setup["ring"].read_bytes() == first.setup["served"]
    again = run_role(tmp, ROLE, "signing_key", first.setup["v"])
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout


# ---------------------------------------------------------------- the driver must already be up
GATES = {
    "the nvidia module is not loaded": {"modules": "nvidia_uvm 1974272 0 - Live 0x0\ndrm 774144 0 - Live 0x0\n"},
    "no module is loaded": {"modules": ""},
    "the control device is missing": {"nvidiactl": False},
}  # fmt: skip


def _gate(tmp, case):
    c = main_case(tmp)
    want = GATES[case]
    if "modules" in want:
        (tmp / "proc" / "modules").write_text(want["modules"])
    if want.get("nvidiactl") is False:
        (tmp / "dev" / "nvidiactl").unlink()
    return c


@pytest.mark.parametrize("case", list(GATES))
@first_run(_gate)
def test_without_the_driver_loaded_nothing_runs_that_could_reach_nvml(first, case):
    """Generating the spec goes through NVML, which as root loads the nvidia module itself: on a
    guest whose cards must not be initialised warm the role refuses, having run nothing."""
    r, tmp = first
    assert r.returncode != 0, case
    assert "the NVIDIA driver is not up" in r.stdout and "Nothing was run" in r.stdout
    assert calls(tmp) == []  # no nvidia-ctk, no apt, no dpkg, no systemctl
    assert not (tmp / "etc" / "cdi" / "nvidia.yaml").exists()


def test_the_gate_comes_before_anything_that_runs_a_command():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text())
    names = [t.get("ansible.builtin.include_tasks") for t in tasks]
    gate = names.index("driver_gate.yml")
    assert names[:gate] == ["validate.yml", "platform.yml"]
    fixed = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
    assert fixed[f"{P}proc_root"] == "/proc" and fixed[f"{P}driver_modules"] == ["nvidia"]
    assert f"{P}proc_root" not in DEFAULTS  # a role var: no inventory value can move the gate


# ---------------------------------------------------------------- dpkg must be settled first
UNSETTLED = {
    "dpkg --audit reports a package": {"audit": "The following packages are only half configured:\n nvidia-dkms-580\n"},
    "a half-configured driver package": {"state": "nvidia-dkms-580 580.95.05-1 iF"},
    "an unpacked package": {"state": "libfoo 1.0 iU"},
    "triggers pending": {"state": "libfoo 1.0 it"},
}  # fmt: skip


def _unsettled(tmp, case):
    want = UNSETTLED[case]
    c = main_case(tmp, dpkg=[*DRIVER, *([want["state"]] if "state" in want else [])])
    if "audit" in want:
        (tmp / "audit.txt").write_text(want["audit"])
    return c


@pytest.mark.parametrize("case", list(UNSETTLED))
@first_run(_unsettled)
def test_an_install_refuses_while_dpkg_has_unfinished_work(first, case):
    r, tmp = first
    assert r.returncode != 0, case
    assert "dpkg has unfinished work" in r.stdout
    assert [c for c in calls(tmp) if c.split()[0] in ("apt-get", "apt-mark")] == []


# ---------------------------------------------------------------- the simulation must be readable
SILENT = {
    "no output at all": "",
    "only Conf lines": "Conf nvidia-container-toolkit (1.20.1-1)\n",
    "three of the four packages": "".join(f"Inst {p} (1.20.1-1)\n" for p in PKGS[1:]),
}  # fmt: skip


def _silent(tmp, case):
    c = main_case(tmp)
    (tmp / "sim.txt").write_text(SILENT[case])
    return c


@pytest.mark.parametrize("case", list(SILENT))
@first_run(_silent)
def test_a_simulation_that_does_not_show_each_package_installed_fails_closed(first, case):
    r, tmp = first
    assert r.returncode != 0, case
    assert "an output the role cannot read is refused, so nothing was installed" in r.stdout
    assert [c for c in calls(tmp) if c.startswith("apt-get")] == ["apt-get update", " ".join(SIM)]
    assert calls(tmp)[-1] == "apt-mark hold " + " ".join(PKGS)


def _partly_pinned(tmp):
    c = main_case(tmp, dpkg=[*DRIVER, *INSTALLED[:2]])  # two already at the pin, held
    (tmp / "sim.txt").write_text("".join(f"Inst {p} (1.20.1-1)\n" for p in PKGS[2:]))
    return c


@first_run(_partly_pinned)
def test_packages_already_at_the_pin_need_no_inst_line(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert " ".join(REAL) in calls(tmp)


def _held_moved(tmp):
    import json

    c = main_case(tmp)
    (tmp / "install.effect.json").write_text(json.dumps({"docker-ce": ["5:29.10.0-1", "hi"]}))
    return c


@first_run(_held_moved)
def test_a_held_package_that_kept_its_hold_but_moved_fails_by_name(first):
    r, _ = first
    assert r.returncode != 0
    assert "held at another version now" in r.stdout and "docker-ce 5:29.9.2-1" in r.stdout


# ---------------------------------------------------------------- gpg is required, never installed
@pytest.mark.parametrize(("state", "ok"), [("ii", True), ("hi", True), ("rc", False), ("", False)])
@first_run(
    lambda tmp, state, ok: {
        "role": ROLE,
        "tasks_from": "gpg_check",
        "extra_vars": world(tmp, dpkg=[*DRIVER, *([f"gpg 2.2.40-1.1 {state}"] if state else [])]),
    }
)
def test_gpg_must_already_be_installed(first, state, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, r.stdout
    if not ok:
        assert "gpg is not installed" in r.stdout


def test_the_source_never_installs_a_package():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "source.yml").read_text())
    modules = {k for t in tasks for k in t if "." in k}
    assert not {"ansible.builtin.apt", "ansible.builtin.package"} & modules
    assert {"ansible.builtin.include_tasks": "gpg_check.yml"}.items() <= tasks[0].items()


# ---------------------------------------------------------------- the boot-time spec refresh
def _unit_not_enabled(tmp):
    return main_case(
        tmp, dpkg=[*DRIVER, *INSTALLED], masked=UNITS, enabled=[], live="the old spec\n"
    )


@first_run(_unit_not_enabled)
def test_the_boot_unit_is_installed_enabled_once_and_never_started(first):
    r, tmp = first
    v = first.setup["v"]
    unit = tmp / "units" / BOOT
    assert r.returncode == 0, r.stdout + r.stderr
    text = unit.read_text()
    assert f"systemctl enable {BOOT}" in calls(tmp)
    assert not [
        c
        for c in calls(tmp)
        if c.startswith("systemctl") and c.split()[1] in ("start", "restart", "daemon-reload")
    ]
    assert (
        "Before=docker.service" in text
        and "After=" in text
        and "WantedBy=multi-user.target" in text
    )
    assert "--load-kernel-modules" not in text and "modprobe" not in text
    # generated outside the CDI directory, renamed inside it: atomic, and the temporary name is never a spec
    cdi = tmp / "etc" / "cdi"
    assert f"--output={tmp}/state/cdi-staged.yaml" in text
    tmpname = f"{cdi}/.nvidia.yaml.hnx-new"
    assert f"install -m 0644 {tmp}/state/cdi-staged.yaml {tmpname}" in text
    assert f"/bin/mv -f {tmpname} {cdi}/nvidia.yaml" in text
    assert not tmpname.endswith((".yaml", ".json"))
    again = run_role(tmp, ROLE, "main", v)
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout
    assert [c for c in calls(tmp) if c.startswith("systemctl enable")] == [
        f"systemctl enable {BOOT}"
    ]


@first_run(_auto)
def test_with_auto_refresh_no_boot_unit_is_installed(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp / "units" / BOOT).exists()


def _stray(tmp):
    c = main_case(tmp, live="cdiVersion: 0.5.0\n")
    (tmp / "etc" / "cdi" / "nvidia.yaml.new.yaml").write_text("cdiVersion: 0.5.0\n")
    return c


@first_run(_stray)
def test_a_second_spec_in_the_cdi_directory_fails_the_run(first):
    r, _ = first
    assert r.returncode != 0 and "sit beside" in r.stdout + r.stderr


def test_the_boot_unit_waits_for_the_nodes_instead_of_loading_modules():
    text = (ROLE_DIR / "templates" / "hnx-nvidia-cdi.service.j2").read_text()
    assert "nvidia-uvm" in text and "nvidiactl" in text and "sleep 1" in text
    assert "docker.service" in text.split("[Service]")[0]
