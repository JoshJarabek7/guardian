import argparse
import logging
import os
import platform
from subprocess import CalledProcessError, run
import urllib.request


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
    system = platform.system().lower()
    machine = platform.machine().lower()
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


def download_file(url, destination):
    try:
        logging.info(f"Downloading {url}")
        with urllib.request.urlopen(url) as response, open(
            destination, "wb"
        ) as out_file:
            data = response.read()  # a `bytes` object
            out_file.write(data)
        logging.info("Download completed successfully.")
    except Exception as e:
        logging.error(f"Failed to download file: {e}")
        raise


def install_package(file_path):
    system = platform.system().lower()
    try:
        if system == "linux":
            if file_path.endswith(".deb"):
                run(["dpkg", "-i", file_path], check=True)
            elif file_path.endswith(".rpm"):
                run(["rpm", "-i", file_path], check=True)
        elif system == "darwin":
            run(["installer", "-pkg", file_path, "-target", "/"], check=True)
        elif system == "windows":
            run(["msiexec", "/i", file_path, "/quiet", "/norestart"], check=True)
        logging.info("Installation completed successfully.")
    except CalledProcessError as e:
        logging.error(f"Failed to install package: {e}")
        raise


parser = argparse.ArgumentParser(description="Fetch and install ClamAV")
parser.add_argument("destination_dir")
parser.add_argument("--cache-dir", default="downloads")

args = parser.parse_args()

logging.basicConfig(level=logging.INFO)

if not os.path.exists(args.destination_dir):
    os.makedirs(args.destination_dir)
    logging.info(f"Created directory {args.destination_dir}")

download_url = get_download_url()
file_name = download_url.split("/")[-1]
file_path = os.path.join(args.cache_dir, file_name)

if not os.path.exists(args.cache_dir):
    os.makedirs(args.cache_dir)

if not os.path.exists(file_path):
    download_file(download_url, file_path)

logging.info(f"Installing {file_name}")
install_package(file_path)
