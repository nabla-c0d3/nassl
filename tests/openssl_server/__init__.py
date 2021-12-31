import shlex

import subprocess
from abc import ABC, abstractmethod
from enum import Enum

import logging
import time
from pathlib import Path
from threading import Thread
from typing import Optional, List

from build_tasks import (
    ModernOpenSslBuildConfig,
    LegacyOpenSslBuildConfig,
    CURRENT_PLATFORM,
    SupportedPlatformEnum,
)


_logger = logging.getLogger(name="tests.openssl_server")


class ClientAuthConfigEnum(Enum):
    """Whether the server asked for client authentication."""

    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class _OpenSslServerIOManager:
    """Thread to log all output from s_server and reply to incoming connections."""

    def __init__(self, s_server_stdout, s_server_stdin):
        self.s_server_stdout = s_server_stdout
        self.s_server_stdin = s_server_stdin
        self.is_server_ready = False

        def read_and_log_and_reply():
            while True:
                s_server_out = self.s_server_stdout.readline()
                if s_server_out:
                    _logger.warning(f"s_server output: {s_server_out}")

                    if b"ACCEPT" in s_server_out:
                        # S_server is ready to receive connections
                        self.is_server_ready = True
                        # Send some data to stdin; required on Windows to jump start modern OpenSSL's s_server
                        self.s_server_stdin.write(b"\n")
                        self.s_server_stdin.flush()

                    if _OpenSslServer.HELLO_MSG in s_server_out:
                        # When receiving the special message, we want s_server to reply
                        self.s_server_stdin.write(b"Hey there")
                        self.s_server_stdin.flush()
                else:
                    break

        self.thread = Thread(target=read_and_log_and_reply, args=())
        self.thread.daemon = True
        self.thread.start()

    def close(self):
        pass
        # TODO(AD): This hangs on Linux; figure it out
        # self.s_server_stdout.close()
        # self.s_server_stdin.close()
        # self.thread.join()


class _OpenSslServer(ABC):
    """A wrapper around OpenSSL's s_server CLI."""

    # On Windows with modern OpenSSL, trying to use ports below 10k will fail for some reason
    _AVAILABLE_LOCAL_PORTS = set(range(18110, 18150))

    _S_SERVER_CMD = (
        "{openssl} s_server -cert {server_cert} -key {server_key} -accept {port}"
        ' -cipher "{cipher}" {verify_arg} {extra_args}'
    )

    _ROOT_PATH = Path(__file__).parent.absolute()

    # Client authentication - files generated using https://gist.github.com/nabla-c0d3/c2c5799a84a4867e5cbae42a5c43f89a
    _CLIENT_CA_PATH = _ROOT_PATH / "client-ca.pem"

    # A special message clients can send to get a reply from s_server
    HELLO_MSG = b"Hello\r\n"

    @classmethod
    def get_server_certificate_path(cls) -> Path:
        return cls._ROOT_PATH / "server-self-signed-cert.pem"

    @classmethod
    def get_server_key_path(cls) -> Path:
        return cls._ROOT_PATH / "server-self-signed-key.pem"

    @classmethod
    def get_client_certificate_path(cls) -> Path:
        return cls._ROOT_PATH / "client-cert.pem"

    @classmethod
    def get_client_key_path(cls) -> Path:
        return cls._ROOT_PATH / "client-key.pem"

    @classmethod
    @abstractmethod
    def get_openssl_path(cls) -> Path:
        pass

    @classmethod
    @abstractmethod
    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        pass

    def __init__(
        self,
        client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
        extra_openssl_args: List[str] = [],
        cipher: Optional[str] = None,
    ) -> None:
        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"

        # Retrieve one of the available local ports; set.pop() is thread safe
        self.port = self._AVAILABLE_LOCAL_PORTS.pop()
        self._process = None
        self._server_io_manager = None
        final_cipher = cipher if cipher else "ALL:COMPLEMENTOFALL"

        self._command_line = self._S_SERVER_CMD.format(
            openssl=self.get_openssl_path(),
            server_key=self.get_server_key_path(),
            server_cert=self.get_server_certificate_path(),
            port=self.port,
            verify_arg=self.get_verify_argument(client_auth_config),
            extra_args=" ".join(extra_openssl_args),
            cipher=final_cipher,
        )

    def __enter__(self):
        _logger.warning(f'Running s_server with command: "{self._command_line}"')
        if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_64, SupportedPlatformEnum.WINDOWS_32]:
            args = self._command_line
        else:
            args = shlex.split(self._command_line)
        try:
            self._process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            self._server_io_manager = _OpenSslServerIOManager(self._process.stdout, self._process.stdin)

            # Block until s_server is ready to accept requests
            attempts_count = 0
            while not self._server_io_manager.is_server_ready:
                time.sleep(1)
                attempts_count += 1

                if self._process.poll() is not None or attempts_count > 3:
                    # s_server has terminated early
                    raise RuntimeError("Could not start s_server")

        except Exception:
            self._terminate_process()
            raise

        return self

    def __exit__(self, *args):
        self._terminate_process()
        return False

    def _terminate_process(self) -> None:
        if self._server_io_manager:
            self._server_io_manager.close()
        self._server_io_manager = None

        if self._process and self._process.poll() is None:
            self._process.terminate()
            self._process.wait()
        self._process = None

        # Free the port that was used; not thread safe but should be fine
        self._AVAILABLE_LOCAL_PORTS.add(self.port)


class LegacyOpenSslServer(_OpenSslServer):
    """A wrapper around the OpenSSL 1.0.0e s_server binary."""

    def __init__(
        self,
        client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
        cipher: Optional[str] = None,
        prefer_server_order: bool = False,
    ) -> None:

        extra_args = []

        if prefer_server_order:
            extra_args.append("-serverpref")

        super().__init__(client_auth_config, extra_args, cipher)

    @classmethod
    def get_openssl_path(cls):
        return LegacyOpenSslBuildConfig(CURRENT_PLATFORM).exe_path

    @classmethod
    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        options = {
            ClientAuthConfigEnum.DISABLED: "",
            ClientAuthConfigEnum.OPTIONAL: f"-verify {cls._CLIENT_CA_PATH}",
            ClientAuthConfigEnum.REQUIRED: f"-Verify {cls._CLIENT_CA_PATH}",
        }
        return options[client_auth_config]


class ModernOpenSslServer(_OpenSslServer):
    """A wrapper around the OpenSSL 1.1.1 s_server binary."""

    @classmethod
    def get_openssl_path(cls):
        return ModernOpenSslBuildConfig(CURRENT_PLATFORM).exe_path

    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        # The verify argument has subtly changed in OpenSSL 1.1.1
        options = {
            ClientAuthConfigEnum.DISABLED: "",
            ClientAuthConfigEnum.OPTIONAL: f"-verify 1 {cls._CLIENT_CA_PATH}",
            ClientAuthConfigEnum.REQUIRED: f"-Verify 1 {cls._CLIENT_CA_PATH}",
        }
        return options[client_auth_config]

    def __init__(
        self,
        client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
        max_early_data: Optional[int] = None,
        cipher: Optional[str] = None,
        prefer_server_order: bool = False,
        groups: Optional[str] = None,
    ) -> None:
        extra_args = []

        if prefer_server_order:
            extra_args.append("-serverpref")

        if groups:
            extra_args.append(f"-groups {groups}")

        if max_early_data is not None:
            # Enable TLS 1.3 early data on the server
            extra_args += ["-early_data", f"-max_early_data {max_early_data}"]

        super().__init__(client_auth_config, extra_args, cipher)
