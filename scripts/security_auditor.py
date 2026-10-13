import io
import platform
import stat
import subprocess
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path


def run_command(command):
    """Run a system command safely."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def audit_system_information():
    print("\n--- SYSTEM INFORMATION ---")
    print(f"Operating system: {platform.system()}")
    print(f"OS release: {platform.release()}")
    print(f"Hostname: {platform.node()}")
    print(f"Python version: {platform.python_version()}")

    result = run_command(["uptime", "-p"])
    if result is not None and result.returncode == 0:
        print(f"System uptime: {result.stdout.strip()}")
    else:
        print("System uptime: Unavailable")


def audit_sudo_group():
    print("\n--- SUDO GROUP AUDIT ---")
    result = run_command(["getent", "group", "sudo"])

    if result is None or result.returncode != 0:
        print("[INFO] Could not retrieve sudo group membership.")
        return

    group_data = result.stdout.strip()
    if not group_data:
        print("[INFO] Sudo group information was not found.")
        return

    parts = group_data.split(":")
    members = parts[3].split(",") if len(parts) > 3 and parts[3] else []

    if members:
        print("Users listed in the sudo group:")
        for member in members:
            print(f"  - {member}")
    else:
        print("No supplementary members listed in the sudo group.")

    print("Review whether each listed user needs administrative access.")


def audit_file_permissions(project_root):
    print("\n--- FILE PERMISSION AUDIT ---")
    test_directory = project_root / "tests"
    findings = 0

    if not test_directory.is_dir():
        print(f"[INFO] Test directory not found: {test_directory}")
        return

    try:
        files = sorted(test_directory.iterdir())
    except OSError as error:
        print(f"[ERROR] Cannot read test directory: {error}")
        return

    for filepath in files:
        if not filepath.is_file():
            continue

        try:
            permissions = filepath.stat().st_mode
        except OSError as error:
            print(f"[ERROR] Cannot inspect {filepath.name}: {error}")
            continue

        if permissions & stat.S_IWOTH:
            print(
                "[HIGH] World-writable file detected: "
                f"{filepath.relative_to(project_root)}"
            )
            findings += 1

    if findings == 0:
        print("No world-writable files detected.")

    print(f"Files flagged for review: {findings}")


def audit_ssh_configuration():
    print("\n--- SSH SECURITY AUDIT ---")
    result = run_command(["sudo", "-n", "/usr/sbin/sshd", "-T"])

    if result is None or result.returncode != 0:
        print(
            "[INFO] Automatic SSH audit skipped because "
            "sudo authentication or SSH access is required."
        )
        print("To inspect manually, run: sudo /usr/sbin/sshd -T")
        return

    settings = {}
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip().lower()

    print("Selected effective SSH settings:")
    for key in (
        "permitrootlogin",
        "passwordauthentication",
        "permitemptypasswords",
        "maxauthtries",
    ):
        print(f"  {key}: {settings.get(key, 'Not reported')}")

    findings = 0

    if settings.get("permitrootlogin") == "yes":
        print("[REVIEW] SSH root login is enabled.")
        findings += 1
    elif settings.get("permitrootlogin") == "prohibit-password":
        print("[REVIEW] Root SSH login may be possible using keys.")
        findings += 1

    if settings.get("passwordauthentication") == "yes":
        print("[REVIEW] SSH password authentication is enabled.")
        findings += 1

    if settings.get("permitemptypasswords") == "yes":
        print("[HIGH] SSH empty-password authentication is enabled.")
        findings += 1

    try:
        attempts = int(settings.get("maxauthtries", "0"))
        if attempts > 4:
            print(f"[REVIEW] SSH permits {attempts} attempts per connection.")
            findings += 1
    except ValueError:
        print("[INFO] Could not interpret maxauthtries.")

    if findings == 0:
        print("No issues detected in the selected SSH settings.")

    print(f"SSH settings flagged for review: {findings}")


def run_audits(project_root):
    print("=" * 60)
    print("PROJECT 06 — LINUX SECURITY AUDITOR")
    print(f"Audit time: {datetime.now().astimezone().isoformat(timespec='seconds')}")
    print("=" * 60)

    audit_system_information()
    audit_sudo_group()
    audit_file_permissions(project_root)
    audit_ssh_configuration()

    print("\n--- AUDIT COMPLETE ---")
    print("Findings require review; they do not prove compromise.")
    print("No system settings were changed by this script.")


def main():
    project_root = Path(__file__).resolve().parent.parent
    report_directory = project_root / "reports"
    report_path = report_directory / "security-audit-report.txt"
    report_directory.mkdir(parents=True, exist_ok=True)

    output = io.StringIO()
    with redirect_stdout(output):
        run_audits(project_root)

    report = output.getvalue()
    report_path.write_text(report, encoding="utf-8")

    print(report, end="")
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
