"""
Webdialer client for Cisco UCM.

Provides click-to-call functionality via the UCM Webdialer SOAP API.

Usage::

    from axltoolkit import WebdialerClient

    client = WebdialerClient(
        username="webdialer_user",
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    # Make a call
    result = client.make_call(
        user="jsmith",
        device="SEPAC7E8AB697E8",
        line="1001",
        destination="1002",
    )

    # End the call
    client.end_call(user="jsmith", device="SEPAC7E8AB697E8", line="1001")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Union

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import WebdialerError

logger = logging.getLogger("axltoolkit.webdialer")


class WebdialerClient(BaseClient):
    """Client for the Cisco UCM Webdialer SOAP API.

    Provides click-to-call and call control features through the Webdialer
    service.

    Args:
        username: Webdialer-enabled user name.
        password: Password.
        server_ip: UCM server IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 10).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = "https://{server}/webdialer/wsdl/wd70.wsdl"
    _BINDING = "{urn:WD70}WebdialerSoapServiceSoapBinding"
    _ENDPOINT = "https://{server}/webdialer/services/WebdialerSoapService70"

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        tls_verify: Union[bool, str] = True,
        timeout: int = 10,
        max_retries: int = 3,
    ):
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
            timeout=timeout,
            max_retries=max_retries,
        )

        wsdl = self._WSDL_PATH.format(server=server_ip)
        self._client = self._create_zeep_client(wsdl)
        self._service = self._client.create_service(
            self._BINDING,
            self._ENDPOINT.format(server=server_ip),
        )

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy."""
        return self._service

    def _build_credential(self) -> Dict[str, str]:
        """Build the Webdialer credential object."""
        return {
            "userID": self._username,
            "password": self._session.auth.password,
        }

    def _build_user_profile(
        self,
        user: str,
        device: str,
        line: str,
        *,
        support_em: bool = False,
        locale: str = "English United States",
        dont_auto_close: bool = True,
        dont_show_call_conf: bool = True,
    ) -> Dict[str, Any]:
        """Build the Webdialer user profile object.

        Args:
            user: The UCM end user ID.
            device: The device name to originate from.
            line: The directory number (line) to use.
            support_em: Whether Extension Mobility is enabled.
            locale: Locale string.
            dont_auto_close: Keep the call control window open.
            dont_show_call_conf: Skip the call confirmation dialog.
        """
        return {
            "user": user,
            "deviceName": device,
            "lineNumber": line,
            "supportEM": support_em,
            "locale": locale,
            "dontAutoClose": dont_auto_close,
            "dontShowCallConf": dont_show_call_conf,
        }

    def make_call(
        self,
        user: str,
        device: str,
        line: str,
        destination: str,
        **profile_kwargs,
    ) -> Dict[str, Any]:
        """Initiate a call via Webdialer.

        Places a call from the specified device/line to the given
        destination number.

        Args:
            user: The UCM end user ID.
            device: The device name to originate the call from
                (e.g. ``"SEPAC7E8AB697E8"``).
            line: The directory number to use (e.g. ``"1001"``).
            destination: The number to call.
            **profile_kwargs: Additional user profile options passed to
                :meth:`_build_user_profile` (e.g. ``support_em=True``).

        Returns:
            The Webdialer response dict with call result information.

        Raises:
            WebdialerError: If the call cannot be placed.

        Example::

            result = client.make_call(
                user="jsmith",
                device="SEPAC7E8AB697E8",
                line="1001",
                destination="1002",
            )
        """
        credential = self._build_credential()
        profile = self._build_user_profile(user, device, line, **profile_kwargs)

        try:
            result = self._service.makeCallSoap(
                in0=credential, in1=destination, in2=profile
            )
        except Fault as fault:
            raise WebdialerError(
                f"Failed to make call to {destination}: {fault}",
                original_exception=fault,
            ) from fault

        return result

    def end_call(
        self,
        user: str,
        device: str,
        line: str,
        **profile_kwargs,
    ) -> Dict[str, Any]:
        """End the active call on a device via Webdialer.

        Args:
            user: The UCM end user ID.
            device: The device name.
            line: The directory number.
            **profile_kwargs: Additional user profile options.

        Returns:
            The Webdialer response dict.

        Raises:
            WebdialerError: If the call cannot be ended.
        """
        credential = self._build_credential()
        profile = self._build_user_profile(user, device, line, **profile_kwargs)

        try:
            result = self._service.endCallSoap(
                in0=credential, in1=profile
            )
        except Fault as fault:
            raise WebdialerError(
                f"Failed to end call on {device}: {fault}",
                original_exception=fault,
            ) from fault

        return result

    def get_device_lines(
        self,
        user: str,
        device: str,
    ) -> Dict[str, Any]:
        """Get the lines available on a device for a user.

        Args:
            user: The UCM end user ID.
            device: The device name.

        Returns:
            The Webdialer response dict with line information.

        Raises:
            WebdialerError: If the query fails.
        """
        credential = self._build_credential()
        profile = {
            "user": user,
            "deviceName": device,
            "lineNumber": "",
            "supportEM": False,
            "locale": "English United States",
        }

        try:
            result = self._service.getDeviceLinesSoap(
                in0=credential, in1=profile
            )
        except Fault as fault:
            raise WebdialerError(
                f"Failed to get device lines for {device}: {fault}",
                original_exception=fault,
            ) from fault

        return result

    def get_port_number(self) -> Dict[str, Any]:
        """Get the Webdialer SOAP service port number.

        Used by clients that need to discover the configured Webdialer
        port (which may differ from the default 8443 depending on UCM
        configuration).

        Returns:
            The Webdialer response dict containing the port number.

        Raises:
            WebdialerError: If the query fails.

        Example::

            info = client.get_port_number()
            print(info)
        """
        try:
            return self._service.getPortNumberSoap()
        except Fault as fault:
            raise WebdialerError(
                f"Failed to get port number: {fault}",
                original_exception=fault,
            ) from fault

    def get_call_status(
        self,
        user: str,
        device: str,
        line: str,
        **profile_kwargs,
    ) -> Dict[str, Any]:
        """Get the current call status for a user/device/line.

        Args:
            user: The UCM end user ID.
            device: The device name.
            line: The directory number.
            **profile_kwargs: Additional user profile options passed to
                :meth:`_build_user_profile`.

        Returns:
            The Webdialer response dict with the current call state
            (idle, ringing, connected, etc.).

        Raises:
            WebdialerError: If the query fails.

        Example::

            status = client.get_call_status(
                user="jsmith",
                device="SEPAC7E8AB697E8",
                line="1001",
            )
        """
        credential = self._build_credential()
        profile = self._build_user_profile(user, device, line, **profile_kwargs)

        try:
            return self._service.getCallStatusSoap(
                in0=credential, in1=profile
            )
        except Fault as fault:
            raise WebdialerError(
                f"Failed to get call status for {device}: {fault}",
                original_exception=fault,
            ) from fault
