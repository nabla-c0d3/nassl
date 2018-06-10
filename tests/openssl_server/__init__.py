import os
import shlex

import subprocess
from enum import Enum

import logging
import time
from typing import Optional

from build_tasks import ModernOpenSslBuildConfig, LegacyOpenSslBuildConfig, CURRENT_PLATFORM, SupportedPlatformEnum


class ClientAuthConfigEnum(Enum):
    """Whether the server asked for client authentication.
    """
    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class OpenSslServerVersion(Enum):
    LEGACY = 1
    MODERN = 2


class OpenSslServer:
    """A wrapper around OpenSSL's s_server CLI.
    """

    _SERVER_CERT_PATH = os.path.join(os.path.dirname(__file__), 'server-self-signed-cert.pem')
    _SERVER_KEY_PATH = os.path.join(os.path.dirname(__file__), 'server-self-signed-key.pem')

    _AVAILABLE_LOCAL_PORTS = set(range(8110, 8150))

    _S_SERVER_CMD = '{openssl} s_server -cert {server_cert} -key {server_key} -accept {port} ' \
                    '-cipher "ALL:COMPLEMENTOFALL" -HTTP {extra_args}'
    _S_SERVER_WITH_OPTIONAL_CLIENT_AUTH_CMD = _S_SERVER_CMD + ' -verify {client_ca}'
    _S_SERVER_WITH_REQUIRED_CLIENT_AUTH_CMD = _S_SERVER_CMD + ' -Verify {client_ca}'

    # Client authentication - files generated using https://gist.github.com/nabla-c0d3/c2c5799a84a4867e5cbae42a5c43f89a
    _CLIENT_CA_PATH = os.path.join(os.path.dirname(__file__), 'client-ca.pem')
    _CLIENT_CERT_PATH = os.path.join(os.path.dirname(__file__), 'client-cert.pem')
    _CLIENT_KEY_PATH = os.path.join(os.path.dirname(__file__), 'client-key.pem')

    @classmethod
    def get_client_certificate_path(cls) -> str:
        return cls._CLIENT_CERT_PATH

    @classmethod
    def get_client_key_path(cls) -> str:
        return cls._CLIENT_KEY_PATH

    def __init__(
            self,
            server_version: OpenSslServerVersion,
            client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
            max_early_data: Optional[int] = None,

    ) -> None:
        # Get the path to the OpenSSL executable from the build tasks
        if server_version == OpenSslServerVersion.MODERN:
            openssl_path = ModernOpenSslBuildConfig(CURRENT_PLATFORM).exe_path
            extra_args = '-early_data'
            if max_early_data is not None:
                extra_args += f' -max_early_data {max_early_data}'

        else:
            openssl_path = LegacyOpenSslBuildConfig(CURRENT_PLATFORM).exe_path
            extra_args = ''

            if max_early_data:
                raise ValueError('Cannot enable early data with legacy OpenSSL')

        self.hostname = 'localhost'
        self.ip_address = '127.0.0.1'

        # Retrieve one of the available local ports; set.pop() is thread safe
        self.port = self._AVAILABLE_LOCAL_PORTS.pop()
        self._process = None

        if client_auth_config == ClientAuthConfigEnum.DISABLED:
            self._command_line = self._S_SERVER_CMD.format(
                openssl=openssl_path,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
                extra_args=extra_args,
            )
        elif client_auth_config == ClientAuthConfigEnum.OPTIONAL:
            self._command_line = self._S_SERVER_WITH_OPTIONAL_CLIENT_AUTH_CMD.format(
                openssl=openssl_path,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
                client_ca=self._CLIENT_CA_PATH,
                extra_args=extra_args,
            )
        elif client_auth_config == ClientAuthConfigEnum.REQUIRED:
            self._command_line = self._S_SERVER_WITH_REQUIRED_CLIENT_AUTH_CMD.format(
                openssl=openssl_path,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
                client_ca=self._CLIENT_CA_PATH,
            )

    def __enter__(self):
        logging.warning('Running s_server: "{}"'.format(self._command_line))
        if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_64, SupportedPlatformEnum.WINDOWS_32]:
            args = self._command_line
        else:
            args = shlex.split(self._command_line)
        self._process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Block until s_server is ready to accept requests
        s_server_out = self._process.stdout.readline()
        logging.warning('s_server output: {}'.format(s_server_out))
        while b'ACCEPT' not in s_server_out:
            s_server_out = self._process.stdout.readline()
            logging.warning('s_server output: {}'.format(s_server_out))

        if self._process.poll() is not None:
            # s_server has terminated early - get the error
            s_server_out = self._process.stdout.readline()
            raise RuntimeError('Could not start s_server: {}'.format(s_server_out))

        # On Travis CI, the server sometimes is still not ready to accept connections when we get here
        # Wait a bit more to make the test suite less flaky
        time.sleep(1)

        return self

    def __exit__(self, *args):
        if self._process and self._process.poll() is None:
            self._process.stdout.close()
            self._process.terminate()
            self._process.wait()
        self._process = None

        # Free the port that was used; not thread safe but should be fine
        self._AVAILABLE_LOCAL_PORTS.add(self.port)
        return False
