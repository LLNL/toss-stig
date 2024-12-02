#!/usr/bin/python3

"""
This script verifies the proper implementation of the TOSS STIG as published by DISA.

Notes:
- Annoucement: https://public.cyber.mil/announcement/disa-releases-the-toss-4-security-technical-implementation-guide/
- Release: `Tri-Lab Operating System Stack (TOSS) 4 STIG - Ver 1, Rel 1`
"""

import argparse

# import codecs
import json
import logging
import logging.config
import os

# import pwd
# import re
import socket
import subprocess
import syslog
import time
import uuid

# import xml.etree.ElementTree as ET

from collections import namedtuple
from datetime import datetime

# Ensure child processes return output in the expected format
os.environ["LC_ALL"] = "C"

logger = logging.getLogger(__name__)
VERBOSE = False

PAM_FILE = "/etc/pam.d/system-auth"
VERSION = None

StigResult = namedtuple("Result", "id, outcome, reason", defaults=[""])

# Default values for STIG rules
EXPECTED_BANNER = """
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
"""


def log_result(control, passing, family="nist", message=None):
    """
    Log sscl result

    - Logging to syslog is using the Elastic Common Schema format.
    """
    if VERBOSE or not passing:
        logger.info("%12s: passing=%s", control, passing)

    cfengine_version, sscl_version = _get_version()

    if not passing and message is None:
        logger.warning(f"{control} ({family}) failed, but no messages recorded.")

    # type munging
    if message is None:
        message = []
    if type(message) == str:
        message = [message]

    ecs_data = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "ecs": {"version": "1.4"},
        "event": {
            "kind": "event",
            "dataset": "lc_isso.sscl",
            "outcome": "success" if passing else "failure",
        },
        "process": {"name": __file__, "executable": os.path.abspath(__file__)},
        "host": {
            "name": socket.gethostname(),
            "cfengine": {"version": cfengine_version},
        },
        "rule": {"name": control, "ruleset": family},  #
        "message": message,
        "stig": {"name": "TOSS 4"},
    }
    syslog.syslog(json.dumps(ecs_data))


def execute(command, timeout=30):
    """
    Fork a process and return the stdout as a string

    Times out after specified time
    """
    logger.debug("Forking command: %s", " ".join(command))
    try:
        process = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "command '%s' timed out after %s seconds...", " ".join(command), timeout
        )
        return (None, None)
    except FileNotFoundError:
        logger.error("command '%s' cannot be located...", " ".join(command))
        return (None, None)
    else:
        return (process.stdout.decode(), process.stderr.decode())


def configure_logging(verbose=False):
    DEFAULT_LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                # 'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                # 'format': '%(levelname)s: %(message)s'
                # "format": "%(asctime)s - %(levelname)s: %(message)s"
                "format": "%(message)s"
            },
        },
        "handlers": {
            "default": {
                "level": "INFO",
                "formatter": "standard",
                "class": "logging.StreamHandler",
            },
            "null": {
                "level": "INFO",
                "formatter": "standard",
                "class": "logging.NullHandler",
            },
        },
        "loggers": {
            "": {"handlers": ["default"], "level": "DEBUG", "propagate": False},
        },
    }

    if verbose:
        DEFAULT_LOGGING["handlers"]["default"]["level"] = "DEBUG"

    logging.config.dictConfig(DEFAULT_LOGGING)


def _parse_file_to_set(filename):
    """
    Reads a file and returns a set of the lines that have content and aren't comments
    """
    try:
        handle = open(filename)
    except FileNotFoundError:
        return set()
    # Get all the lines from the files that aren't empty or commented out
    lines = [
        line for line in handle.readlines() if line.strip() and not line.startswith("#")
    ]
    # Trim any trailing comments on the same line
    lines = [line.split("#")[0].strip() for line in lines]
    return set(lines)


def _parse_sudoers(filepath="/etc/sudoers"):
    """
    Passive Approach by parsing sudoers
    """
    sudoers_file = [line.strip() for line in open(filepath).readlines()]
    sudoers_file = [line for line in sudoers_file if line]  # Prune empty lines

    sudoers = []
    for line in sudoers_file:
        if line.startswith("#includedir"):  # This is a real includedir to check
            # sudoers.append(line)
            _, path = line.split()
            for included_file in os.listdir(path):
                inner_path = os.path.join(path, included_file)
                try:
                    sudoers.extend(_parse_sudoers(inner_path))
                except IsADirectoryError:
                    # This probably indicates that something is amiss
                    # since there shouldn't normally be sub-directories here
                    logger.warning(
                        f"Tried parsing sudoers directory {inner_path}, skipping..."
                    )
            continue
        if line.startswith("#"):  # This is the comment
            continue
        if line.startswith("Defaults"):  # This is not the important bit
            continue
        sudoers.append(line)

    # Join lines that are broken up with a backslash
    sudoers = "\n".join(sudoers).replace("\\\n", "").splitlines()

    return sudoers


def toss_04_010000(expected_banner: str = None):
    """
    Rule Title: TOSS must display the Standard Mandatory DoD Notice and Consent Banner
    or equivalent US Government Agency Notice and Consent Banner before granting local
    or remote access to the system.

    Vul ID: V-252911
    STIG ID: TOSS-04-010000
    Severity: CAT II
    Classification: Unclass
    """
    if expected_banner is None:
        expected_banner = EXPECTED_BANNER

    def _flatten_banner(banner):
        return "".join(banner.split()).lower()

    expected_banner = _flatten_banner(expected_banner)
    system_banner = _flatten_banner(open("/etc/issue").read())

    if system_banner != expected_banner:
        reason = "Content of `/etc/issue` does not match expected value"
        return StigResult("TOSS-04-010000", "failure", reason)
    else:
        return StigResult("TOSS-04-010000", "success")


def toss_04_010010(ca_path: str = "/etc/sssd/pki/sssd_auth_ca_db.pem"):
    """
    Rule Title: TOSS, for PKI-based authentication, must validate certificates by
    constructing a certification path (which includes status information) to an accepted
    trust anchor.

    Vul ID: V-252912
    STIG ID: TOSS-04-010010
    Severity: CAT II Classification: Unclass

    TODO:
    - Add a way to check if PKI Authentication is disabled
        - maybe just if `sssd` is disabled / missing?
    """
    (stdout, stderr) = execute(["openssl", "x509", "-text", "-in", ca_path])

    if "Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI" in stdout:
        return StigResult("TOSS-04-010010", "success")
    else:
        return StigResult("TOSS-04-010010", "failure", stdout)


def toss_04_010020(fake_password: str = None):
    """
    Rule Title: TOSS, for PKI-based authentication, must enforce authorized access to the corresponding private key.

    Vul ID: V-252913
    STIG ID: TOSS-04-010020
    Severity: CAT II
    Classification: Unclass

    TODO:
    - Add check for when PKI Authentication is not allowed, this would be not applicable.
    - Submit fix to DISA, command should use `-N` rather than `-n` in fix text.
    """

    # TODO: Populate with list of key paths
    keys = []

    key_status = []  # Tuples of (keypath, )
    all_encrypted = True

    if fake_password is None:
        fake_password = str(uuid.uuid1())

    for key in keys:
        (stdout, stderr) = execute(
            ["sudo", "ssh-keygen", "-y", "-P", fake_password, "-f", key]
        )
        if "incorrect passphrase supplied to decrypt private key" in stdout:
            key_status.append((key, "encrypted"))
        else:
            key_status.append((key, "not encrypted"))
            all_encrypted = False

    if all_encrypted:
        return StigResult(
            "TOSS-04-010020",
            "success",
        )
    else:
        return StigResult(
            "TOSS-04-010020",
            "failure",
        )


def toss_04_xxxxxx():
    """
    Rule Title: xxx

    """
    return StigResult("TOSS-04-xxxxxx", "success")


def toss_04_xxxxxx():
    """
    Rule Title: xxx

    """
    return StigResult("TOSS-04-xxxxxx", "success")


def toss_04_xxxxxx():
    """
    Rule Title: xxx

    """
    return StigResult("TOSS-04-xxxxxx", "success")


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description="Run the TOSS STIG against a host to check compliance"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose
    configure_logging(verbose=args.verbose)

    toss_stig_controls = [func for func in globals() if func.startswith("toss_04")]
    for control in toss_stig_controls:
        print(control, type(control))
        print(globals()[control]())

    run_time = time.time() - start_time
    logger.info(f"STIG Validation Runtime: {run_time}")


if __name__ == "__main__":
    main()
