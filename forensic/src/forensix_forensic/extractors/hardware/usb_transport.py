"""Shared USB bulk-transfer transport for hardware forensic acquisition modules.

Provides a thin, retrying wrapper around ``pyusb`` (``usb.core``) for all
hardware acquisition modules.  The class handles:

*  USB device claim and configuration.
*  Bulk OUT / IN endpoint auto-detection from interface descriptor.
*  ``bulk_write`` with automatic retry on ``STALL`` (up to *max_retries*).
*  ``bulk_read``  with ``bytes`` return type, raising :class:`UsbTimeoutError`
   on timeout and :class:`UsbStallError` on permanent stall.
*  Async adapter so callers can ``await transport.write(...)`` without blocking
   the event loop (wraps the synchronous pyusb calls in a thread-pool executor).
*  Context-manager support for guaranteed resource cleanup.

The module imports ``usb.core`` lazily inside :class:`UsbBulkTransport.__init__`
so that the rest of the package does not hard-depend on pyusb being installed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Default timeouts and retry policy
DEFAULT_TIMEOUT_MS: int = 10_000  # 10 seconds per USB operation
DEFAULT_MAX_RETRIES: int = 3
RETRY_BACKOFF_MS: int = 500  # 0.5 s between retries


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class UsbTransportError(RuntimeError):
    """Base class for USB transport failures."""


class UsbTimeoutError(UsbTransportError):
    """Raised when a USB bulk operation times out."""


class UsbStallError(UsbTransportError):
    """Raised when a USB STALL condition persists after all retries."""


class UsbDeviceNotFoundError(UsbTransportError):
    """Raised when no matching USB device is found."""


# ---------------------------------------------------------------------------
# Transport implementation
# ---------------------------------------------------------------------------


class UsbBulkTransport:
    """Retrying, async-capable wrapper around a pyusb bulk interface.

    Parameters
    ----------
    vid:
        USB Vendor ID (integer, e.g. ``0x05C6`` for Qualcomm).
    pid:
        USB Product ID (integer, e.g. ``0x9008`` for EDL mode).
    timeout_ms:
        Per-operation timeout in milliseconds.  Passed directly to pyusb.
    max_retries:
        Number of retries on STALL before raising :class:`UsbStallError`.
    interface:
        USB interface index (default ``0``).
    alt_setting:
        Alternate setting index (default ``0``).
    ep_out_addr:
        Force a specific OUT endpoint address.  If ``None`` the first OUT
        bulk endpoint is auto-detected from the interface descriptor.
    ep_in_addr:
        Force a specific IN endpoint address.  If ``None`` the first IN
        bulk endpoint is auto-detected.
    """

    def __init__(
        self,
        vid: int,
        pid: int,
        *,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        interface: int = 0,
        alt_setting: int = 0,
        ep_out_addr: int | None = None,
        ep_in_addr: int | None = None,
    ) -> None:
        try:
            import usb.core  # type: ignore
            import usb.util  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "pyusb is required for hardware acquisition: pip install pyusb"
            ) from exc

        self._usb_core = usb.core
        self._usb_util = usb.util
        self._vid = vid
        self._pid = pid
        self._timeout_ms = timeout_ms
        self._max_retries = max_retries
        self._interface = interface
        self._alt_setting = alt_setting
        self._ep_out_addr = ep_out_addr
        self._ep_in_addr = ep_in_addr

        self._device: Any = None
        self._ep_out: Any = None
        self._ep_in: Any = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> UsbBulkTransport:
        self.open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    async def __aenter__(self) -> UsbBulkTransport:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.open)
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Device lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Find, claim, and configure the USB device.

        Raises
        ------
        UsbDeviceNotFoundError
            If no device matching *vid*/*pid* is present on the bus.
        """
        device = self._usb_core.find(idVendor=self._vid, idProduct=self._pid)
        if device is None:
            raise UsbDeviceNotFoundError(
                f"No USB device found: VID=0x{self._vid:04X} PID=0x{self._pid:04X}. "
                "Ensure the device is in the correct download mode and USB cable is connected."
            )

        # Detach kernel driver if active (Linux/macOS only; no-op on Windows)
        try:
            if device.is_kernel_driver_active(self._interface):
                device.detach_kernel_driver(self._interface)
        except (NotImplementedError, AttributeError):
            pass  # Windows — no kernel driver management needed

        device.set_configuration()

        # Get the target interface/alt-setting
        intf = device[0][(self._interface, self._alt_setting)]

        # Auto-detect endpoints if not overridden
        ep_out = None
        ep_in = None

        import usb.util

        for ep in intf:
            is_bulk = usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            if not is_bulk:
                continue
            direction = usb.util.endpoint_direction(ep.bEndpointAddress)
            if (
                direction == usb.util.ENDPOINT_OUT
                and ep_out is None
                and (self._ep_out_addr is None or ep.bEndpointAddress == self._ep_out_addr)
            ):
                ep_out = ep
            elif (
                direction == usb.util.ENDPOINT_IN
                and ep_in is None
                and (self._ep_in_addr is None or ep.bEndpointAddress == self._ep_in_addr)
            ):
                ep_in = ep

        if ep_out is None:
            raise UsbTransportError(f"No BULK OUT endpoint found on interface {self._interface}")
        if ep_in is None:
            raise UsbTransportError(f"No BULK IN endpoint found on interface {self._interface}")

        self._device = device
        self._ep_out = ep_out
        self._ep_in = ep_in

        logger.debug(
            "USB device opened: VID=0x%04X PID=0x%04X EP_OUT=0x%02X EP_IN=0x%02X",
            self._vid,
            self._pid,
            ep_out.bEndpointAddress,
            ep_in.bEndpointAddress,
        )

    def close(self) -> None:
        """Release all USB resources."""
        if self._device is not None:
            from contextlib import suppress

            with suppress(Exception):
                self._usb_util.dispose_resources(self._device)
            self._device = None
            self._ep_out = None
            self._ep_in = None
            logger.debug("USB device closed.")

    # ------------------------------------------------------------------
    # Synchronous bulk I/O (used inside executor for async callers)
    # ------------------------------------------------------------------

    def write_sync(self, data: bytes | bytearray) -> int:
        """Write *data* to the bulk OUT endpoint synchronously.

        Retries up to *max_retries* times on STALL.

        Returns
        -------
        int
            Number of bytes actually written.

        Raises
        ------
        UsbStallError
            If the endpoint STALLs on every retry attempt.
        UsbTimeoutError
            If the write times out.
        """
        import usb.core

        if self._ep_out is None:
            raise UsbTransportError("Transport not opened. Call open() first.")

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                written: int = self._ep_out.write(data, timeout=self._timeout_ms)
                logger.debug("USB write: %d bytes (attempt %d)", written, attempt)
                return written
            except usb.core.USBTimeoutError as exc:
                raise UsbTimeoutError(f"USB write timed out after {self._timeout_ms} ms") from exc
            except usb.core.USBError as exc:
                last_exc = exc
                if "STALL" in str(exc).upper() or "PIPE" in str(exc).upper():
                    # Clear STALL and retry
                    from contextlib import suppress

                    with suppress(Exception):
                        self._ep_out.clear_halt()
                    if attempt < self._max_retries:
                        import time

                        time.sleep(RETRY_BACKOFF_MS / 1000)
                        continue
                raise UsbTransportError(f"USB write error: {exc}") from exc

        raise UsbStallError(
            f"Bulk OUT endpoint STALLed after {self._max_retries} attempts"
        ) from last_exc

    def read_sync(self, length: int) -> bytes:
        """Read up to *length* bytes from the bulk IN endpoint synchronously.

        Returns
        -------
        bytes
            The received data (may be shorter than *length* if the device
            sends a short packet).

        Raises
        ------
        UsbTimeoutError
            If no data is received within *timeout_ms*.
        UsbStallError
            If the endpoint STALLs on every retry attempt.
        """
        import usb.core

        if self._ep_in is None:
            raise UsbTransportError("Transport not opened. Call open() first.")

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                data = bytes(self._ep_in.read(length, timeout=self._timeout_ms))
                logger.debug("USB read: %d bytes (attempt %d)", len(data), attempt)
                return data
            except usb.core.USBTimeoutError as exc:
                raise UsbTimeoutError(
                    f"USB read timed out after {self._timeout_ms} ms (expected {length} bytes)"
                ) from exc
            except usb.core.USBError as exc:
                last_exc = exc
                if "STALL" in str(exc).upper() or "PIPE" in str(exc).upper():
                    from contextlib import suppress

                    with suppress(Exception):
                        self._ep_in.clear_halt()
                    if attempt < self._max_retries:
                        import time

                        time.sleep(RETRY_BACKOFF_MS / 1000)
                        continue
                raise UsbTransportError(f"USB write error: {exc}") from exc

        raise UsbStallError(
            f"Bulk IN endpoint STALLed after {self._max_retries} attempts"
        ) from last_exc

    def read_exact_sync(self, length: int) -> bytes:
        """Read exactly *length* bytes, issuing multiple reads if needed.

        Some USB hosts return short packets; this method keeps reading
        until the full *length* is satisfied or an error occurs.
        """
        buf = bytearray()
        remaining = length
        while remaining > 0:
            chunk = self.read_sync(remaining)
            if not chunk:
                raise UsbTransportError(
                    f"USB read returned empty data (received {len(buf)}/{length} bytes)"
                )
            buf.extend(chunk)
            remaining -= len(chunk)
        return bytes(buf)

    # ------------------------------------------------------------------
    # Async bulk I/O (non-blocking wrappers for asyncio callers)
    # ------------------------------------------------------------------

    async def write(self, data: bytes | bytearray) -> int:
        """Async wrapper around :meth:`write_sync`."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.write_sync, data)

    async def read(self, length: int) -> bytes:
        """Async wrapper around :meth:`read_sync`."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.read_sync, length)

    async def read_exact(self, length: int) -> bytes:
        """Async wrapper around :meth:`read_exact_sync`."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.read_exact_sync, length)
