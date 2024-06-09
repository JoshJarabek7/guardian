import argparse
import logging
import os
import platform
import subprocess


def get_linux_package_type():
    if os.path.exists("/etc/debian_version"):
        return "deb"
    elif os.path.exists("/etc/redhat-release"):
        return "rpm"
    else:
        raise Exception(
            "Unsupported Linux distribution. Only Debian-based and RPM-based distributions are supported."
        )


def get_download_url():
    system = platform.system().lower()  # Ex: 'linux', 'darwin', 'windows'
    machine = platform.machine().lower()  # Ex: 'x86_64', 'i686', 'arm64'
    CLAMAV_GENERAL_DOWNLOAD_URL = "https://www.clamav.net/downloads/production"
    CLAMAV_VERSION_RC = "clamav-1.4.0-rc"
    CLAMAV_URL_PREFIX = f"{CLAMAV_GENERAL_DOWNLOAD_URL}/{CLAMAV_VERSION_RC}"

    if system == "darwin":
        return f"{CLAMAV_URL_PREFIX}.macos.universal.pkg"
    elif system == "linux":
        package_type = get_linux_package_type()
        return f"{CLAMAV_URL_PREFIX}.{system}.{machine}.{package_type}"
    elif system == "windows":
        if "amd64" in machine or "x86_64" in machine:
            return f"{CLAMAV_URL_PREFIX}.win.x64.msi"
        elif "win32" in machine or "i386" in machine:
            return f"{CLAMAV_URL_PREFIX}.win.win32.msi"
    raise Exception(f"Unsupported system {system} with architecture {machine}")


parser = argparse.ArgumentParser(description="Fetch and install ClamAV")
parser.add_argument("destination_dir")
parser.add_argument("--cache-dir", default="downloads")

args = parser.parse_args()

logging.basicConfig(level=logging.INFO)

# Ensure destination directory exists
logging.info(f"Creating directory {args.destination_dir}")

if not os.path.exists(args.destination_dir):
    os.makedirs(args.destination_dir)

download_url = get_download_url()
file_name = download_url.split("/")[-1]
file_path = os.path.join(args.cache_dir, file_name)

# Download the appropriate binary/package
if not os.path.exists(file_path):
    logging.info(f"Downloading {download_url}")
    if not os.path.exists(args.cache_dir):
        os.makedirs(args.cache_dir)
    subprocess.check_call(["curl", "--location", "--output", file_path, download_url])

logging.info(f"Installing {file_name}")
system = platform.system().lower()

if system == "linux":
    if file_name.endswith(".deb"):
        subprocess.check_call(["sudo", "dpkg", "-i", file_path])
    elif file_name.endswith(".rpm"):
        subprocess.check_call(["sudo", "rpm", "-i", file_path])
elif system == "darwin":
    subprocess.check_call(["sudo", "installer", "-pkg", file_path, "-target", "/"])
elif system == "windows":
    subprocess.check_call(["msiexec", "/i", file_path, "/quiet", "/norestart"])
else:
    raise Exception(f"Unsupported system {system}")
