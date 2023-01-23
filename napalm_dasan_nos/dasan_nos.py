# Copyright 2022 4th Utility Holdings Limited. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for DasanNOS.

Read https://napalm.readthedocs.io for more information.
"""

import os
import re
import socket
from typing import Any, Dict, List, Union

import napalm.base.utils
import napalm.base.helpers
from napalm.base import NetworkDriver, models
from napalm.base.netmiko_helpers import netmiko_args

from napalm.base.exceptions import (
    ConnectionException,
    ConnectionClosedException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
)

templates = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "utils/textfsm_templates/"
)
os.environ["NET_TEXTFSM"] = templates

class DasanNOSDriver(NetworkDriver):
    """Napalm driver for DasanNOS."""

    def __init__(self, hostname: str, username: str, password: str, timeout: int = 60, optional_args: Dict[str, Any] = None):
        """Constructor."""
        self.platform = "dasan_nos"

        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args or {}

        self.port = self.optional_args.get("port", 22)
        self.username = self.optional_args.get("username", username)
        self.password = self.optional_args.get("password", password)

        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", self.port)

    def open(self) -> None:
        self.device = self._netmiko_open(
            "generic", netmiko_optional_args=self.netmiko_optional_args
        )

        """Since Dasan NOS always returns True on connect() we check the output for substring Login incorrect after connecting."""
        pattern = "(>|Login incorrect)"
        output = self.device._test_channel_read(pattern=pattern)

        pattern = "Login incorrect"
        if re.search(pattern, output):
            self.close()
            msg = "Authentication failure: unable to connect to "
            msg += f"{self.hostname}:{self.port} "
            msg += output.strip()
            raise ConnectionException(msg)

    def close(self) -> None:
        self._netmiko_close()

    def _enable(self) -> None:
        self.device.send_command("enable", expect_string=r"#")

    def _send_command(self, command: Union[str, List], use_textfsm: bool = False) -> Union[str, Dict[str, str]]:
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        current_prompt = self.device.find_prompt().strip()
        terminating_char = current_prompt[-1]
        pattern = r"[>#{}]\s*$".format(terminating_char) 
        try:
            output = ""
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd, use_textfsm=use_textfsm)
                    if not use_textfsm:
                        output = output.strip()
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command, use_textfsm=use_textfsm,expect_string=pattern)
                if not use_textfsm:
                    output = output.strip()

            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    @staticmethod
    def _format_uptime(uptime: str) -> float:
        """Format uptime in seconds"""
        # e.g. 9 days 6 hours 17 minutes 25 seconds
        uptime_sec = 0.0
        regex = re.compile(r"(?:(?P<days>\d+) days )?(?:(?P<hours>\d+) hours )?(?:(?P<minutes>\d+) minutes )?(?P<seconds>\d+) seconds")
        units = regex.match(uptime).groupdict()

        for unit in units:
            if unit == "days":
                uptime_sec += int(units[unit]) * 86400
            elif unit == "hours":
                uptime_sec += int(units[unit]) * 3600
            elif unit == "minutes":
                uptime_sec += int(units[unit]) * 60
            elif unit == "seconds":
                uptime_sec += int(units[unit])

        return int(uptime_sec)

    def cli(self, commands: List[str], encoding: str = "text") -> Dict[str, Union[str, Dict[str, Any]]]:
        if encoding != "text":
            raise NotImplementedError(f"{encoding} is not a supported encoding")
        cli_output = dict()
        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            if "Incorrect usage" in output:
                raise ValueError(f"Unable to execute command {command}")
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_config(self, retrieve: str = "all", full: bool = False, sanitized: bool = False) -> models.ConfigDict:
        self._enable()

        data = {
            "startup": "",
            "running": "",
            "candidate": "",
        }

        if retrieve in ["all", "running"]:
            command = "show running-config"
            config = self._send_command(command)
            data["running"] = config

        if retrieve in ["all", "startup"]:
            command = "show startup-config"
            config = self._send_command(command)
            data["startup"] = config

        if sanitized:
            filters = {
                r"(mgmt-mode tr-069 access id \S+\s+password\s+).*$": r"\1<removed>",
                r"(onu auto-upgrade firmware.*\s+ftp\s+\S+\s+\S+\s+).*$": r"\1<removed>",
                r"(snmp trap\S+\s+\S+\s+).*$": r"\1<removed>",
                r"(snmp community\s+\S+\s+).*$": r"\1<removed>"
            }

            data = napalm.base.helpers.sanitize_configs(data, filters)

        return data

    def get_environment(self) -> models.EnvironmentDict:
        self._enable()

        output = {}
        commands = ["show cpuload", "show memory", "show status fan", "show status temp", "show status power"]
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}, "memory": {}}

        data["memory"] = {
            "available_ram": int(output["show memory"][0]["mem_total"]),
            "used_ram": int(output["show memory"][0]["mem_used"])
        }

        for entry in output["show status fan"]:
            key = entry["fan_name"] + "-" + entry["fan_index"]
            status = (entry["fan_status"] == "RUN")

            data["fans"][key] = {
                "status": status
            }

        for entry in output["show status temp"]:
            key = entry["temp_name"]
            value = float(entry["temp_value"])
            threshold_low = float(entry["temp_threshold_low"])
            threshold_high = float(entry["temp_threshold_high"])
            is_critical = (value < threshold_low or value > threshold_high)
            is_alert = (value < (threshold_low + (threshold_low * 0.10)) or value > (threshold_high - (threshold_high * 0.10)))

            data["temperature"][key] = {
                "temperature": value,
                "is_alert": is_alert,
                "is_critical": is_critical
            }

        for entry in output["show status power"]:
            key = entry["power_name"]
            status = (entry["power_status"] == "OK")

            data["power"][key] = {
                "status": status,
                "capacity": None,
                "output": None
            }

        for entry in output["show cpuload"]:
            key = "CPU"
            usage = float(entry["cpu_average_1min"])

            data["cpu"][key]= {
                "%usage": usage
            }

        return data

    def get_facts(self) -> models.FactsDict:
        self._enable()
        
        output = {}
        commands = ["show system", "show uptime", "show ip interface brief", "show running-config hostname"]
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {
            "uptime": self._format_uptime(output["show uptime"][0]["uptime"]),
            "vendor": "Dasan",
            "os_version": output["show system"][0]["sw_version"],
            "serial_number": output["show system"][0]["serial"],
            "model": output["show system"][0]["model"],
            "hostname": output["show running-config hostname"][0]["hostname"],
            "fqdn": "",
            "interface_list": napalm.base.utils.string_parsers.sorted_nicely(
                tuple(entry["interface"] for entry in output["show ip interface brief"])
            ),
        }

        return data

    def is_alive(self) -> models.AliveDict:
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        try:
            # Try sending ASCII null byte to maintain the connection alive
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}

        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {"is_alive": False}
