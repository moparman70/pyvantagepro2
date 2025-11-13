"""pyvantagepro2.device-------------------Allows data query of Davis Vantage Pro2 devices."""

from __future__ import annotations

from datetime import datetime, timedelta
import struct

from aioretry import RetryInfo, RetryPolicyStrategy, retry
import aioserial
from async_property import async_cached_property

from .parser import (
    ArchiveDataParserRevB,
    DmpHeaderParser,
    DmpPageParser,
    LoopDataParserRevB,
    VantageProCRC,
    pack_datetime,
    pack_dmp_date_time,
    unpack_datetime,
)
from .utils import ListDict, is_bytes


class NoDeviceException(Exception):
    """Can not access weather station."""

    value = __doc__


class BadAckException(Exception):
    """No valid acknowledgement."""

    def __str__(self):
        """Return status."""

        return self.__doc__


class BadCRCException(Exception):
    """No valid checksum."""

    def __str__(self):
        """Return status."""

        return self.__doc__


class BadDataException(Exception):
    """No valid data."""

    def __str__(self):
        """Return status."""

        return self.__doc__


def retry_policy(info: RetryInfo) -> RetryPolicyStrategy:
    """Retry policy."""

    return info.fails > 3, 1


class VantagePro2:
    """Communicates with the station by sending commands, reads the binary data and parsing it into usable scalar values.

    :param link: A `PyLink` connection.
    """

    # device reply commands
    WAKE_STR = "\n"
    WAKE_ACK = "\n\r"
    ACK = "\x06"
    NACK = "\x21"
    DONE = "DONE\n\r"
    CANCEL = "\x18"
    ESC = "\x1b"
    OK = "\n\rOK\n\r"

    def __init__(self, link: aioserial.AioSerial) -> None:
        """Initialize some shit."""

        self.link = link
        # self._check_revision()
        self.RevA = False
        self.RevB = True

    @classmethod
    async def from_url(cls, url, timeout=10):
        """Get device from url."""

        link = aioserial.AioSerial(port=url, baudrate=115200, timeout=timeout)
        return cls(link)

    @retry(retry_policy)
    async def wake_up(self) -> bool:
        """Wakeup the station console."""

        wait_ack = self.WAKE_ACK
        await self.link.write_async(self.WAKE_STR.encode())
        ack = await self.link.read_async(len(wait_ack))
        if wait_ack == ack.decode():
            return True
        # Sometimes we have a 1byte shift from Vantage Pro and that's why wake up doesn't work anymore
        # We just shift another 1byte to be aligned in the serial buffer again.
        await self.link.read_async(1)
        raise NoDeviceException

    @retry(retry_policy)
    async def send(self, data, wait_ack=None, timeout=None):
        """Sends data to station.

        :param data: Can be a byte array or an ASCII command. If this is
           the case for an ascii command, a <LF> will be added.

        :param wait_ack: If `wait_ack` is not None, the function must check
           that acknowledgement is the one expected.

        :param timeout: Define this timeout when reading ACK from link﻿.
        """
        if await is_bytes(data):
            await self.link.write_async(data)
        else:
            await self.link.write_async((f"{data}\n").encode())
        if wait_ack is None:
            return True
        ack = await self.link.read_async(len(wait_ack))
        if wait_ack == ack:
            return True
        raise BadAckException

    @retry(retry_policy)
    async def read_from_eeprom(self, hex_address, size):
        """Reads from EEPROM the `size` number of bytes starting at the `hex_address`. Results are given as hex strings."""

        await self.link.write_async(
            (f"{'EEBRD '}{hex_address}{' '}{size:02d}\n").encode()
        )
        ack = await self.link.read_async(len(self.ACK))
        if ack.decode() == self.ACK:
            data = await self.link.read_async(size + 2)  # 2 bytes for CRC
            if VantageProCRC(data).check():
                return data[:-2]
            raise BadCRCException
        raise BadAckException

    async def gettime(self):
        """Returns the current datetime of the console."""

        await self.wake_up()
        await self.send("GETTIME", self.ACK)
        data = await self.link.read_async(8)
        if isinstance(data, bytes):
            return unpack_datetime(data)
        return None

    async def settime(self, dtime):
        """Set the given `dtime` on the station."""

        await self.wake_up()
        await self.send("SETTIME", self.ACK)
        await self.send(pack_datetime(dtime), self.ACK)

    async def get_current_data(self):
        """Returns the real-time data as a `Dict`."""

        await self.wake_up()
        await self.send("LOOP 1", self.ACK)
        current_data = await self.link.read_async(99)
        if isinstance(current_data, bytes):
            if self.RevB:
                return LoopDataParserRevB(current_data, datetime.now())
            raise NotImplementedError("Do not support RevB data format")
        return None

    async def get_archives(self, start_date=None, stop_date=None):
        """Get archive records until `start_date` and `stop_date` as ListDict.

        :param start_date: The beginning datetime record.

        :param stop_date: The stopping datetime record.
        """
        generator = self._get_archives_generator(start_date, stop_date)
        archives = ListDict()
        dates = []
        async for item in generator:
            if item["Datetime"] not in dates:
                archives.append(item)
                dates.append(item["Datetime"])
        return archives.sorted_by("Datetime")

    async def _get_archives_generator(self, start_date=None, stop_date=None):
        """Get archive records generator until `start_date` and `stop_date`."""

        await self.wake_up()
        # 2001-01-01 01:01:01
        start_date = start_date or datetime(2001, 1, 1, 1, 1, 1)
        stop_date = stop_date or datetime.now()
        # round start_date, with the archive period to the previous record
        period = await self.archive_period  # pyright: ignore[reportGeneralTypeIssues]
        minutes = start_date.minute % period
        start_date = start_date - timedelta(minutes=minutes)
        await self.send("DMPAFT", self.ACK)
        # I think that date_time_crc is incorrect...
        await self.link.write_async(await pack_dmp_date_time(start_date))
        # timeout must be at least 2 seconds
        ack = await self.link.read_async(len(self.ACK))
        if ack != self.ACK:
            raise BadAckException
        # Read dump header and get number of pages
        header = DmpHeaderParser(await self.link.read_async(6))
        # Write ACK if crc is good. Else, send cancel.
        if header.crc_error:
            await self.link.write_async(self.CANCEL.encode())
            raise BadCRCException
        else:
            await self.link.write_async(self.ACK.encode())
        finish = False
        r_index = 0
        for _i in range(header["Pages"]):
            # Read one dump page
            try:
                dump = await self._read_dump_page()
            except (BadCRCException, BadDataException):
                finish = True
                break
            # Get the 5 raw records
            raw_records = dump["Records"]
            # loop through archive records
            offsets = zip(range(0, 260, 52), range(52, 261, 52), strict=False)
            # offsets = [(0, 52), (52, 104), ... , (156, 208), (208, 260)]
            for offset in offsets:
                raw_record = raw_records[offset[0] : offset[1]]
                if self.RevB:
                    record = ArchiveDataParserRevB(raw_record)
                else:
                    msg = "Do not support RevA data format"
                    raise NotImplementedError(msg)
                # verify that record has valid data, and store
                r_time = record["Datetime"]
                if r_time is None:
                    finish = True
                    break
                elif r_time <= stop_date:
                    if start_date < r_time:
                        not_in_range = False
                        msg = "Record-%.4d - Datetime : %s" % (r_index, r_time)  # noqa: UP031
                        yield record
                    else:
                        not_in_range = True
                else:
                    finish = True
                    break
                r_index += 1
            if finish:
                await self.link.write_async(self.ESC.encode())
                break
            elif not_in_range:
                msg = "Page is not in the datetime range"
                await self.link.write_async(self.ESC.encode())
                break
            else:
                await self.link.write_async(self.ACK.encode())

    @async_cached_property
    async def archive_period(self) -> int:
        """Returns number of minutes in the archive period."""

        return struct.unpack(b"B", await self.read_from_eeprom("2D", 1))[0]

    @async_cached_property
    async def timezone(self):
        """Returns timezone offset as string."""

        data = await self.read_from_eeprom("14", 3)
        offset, gmt = struct.unpack(b"HB", data)
        if gmt == 1:
            return "GMT+%.2f" % (offset / 100)
        return "Localtime"

    @async_cached_property
    async def firmware_date(self):
        """Return the firmware date code."""

        await self.wake_up()
        await self.send("VER", self.OK)
        data = await self.link.read_async(13)
        return datetime.strptime(data.decode().strip("\n\r"), "%b %d %Y").date()

    @async_cached_property
    async def firmware_version(self):
        """Returns the firmware version as string."""

        await self.wake_up()
        await self.send("NVER", self.OK)
        data = await self.link.read_async(6)
        return data.decode().strip("\n\r")

    @async_cached_property
    async def diagnostics(self):
        """Return the Console Diagnostics report. (RXCHECK command)."""

        await self.wake_up()
        await self.send("RXCHECK", self.OK)
        data = await self.link.read_async(4048)
        data = [int(i) for i in data]
        return {
            "total_received": data[0],
            "total_missed": data[1],
            "resyn": data[2],
            "max_received": data[3],
            "crc_errors": data[4],
        }

    @retry(retry_policy)
    async def _read_dump_page(self):
        """Read, parse and check a DmpPage."""

        raw_dump = await self.link.read_async(267)
        if len(raw_dump) != 267:
            await self.link.write_async(self.NACK.encode())
            raise BadDataException
        dump = DmpPageParser(raw_dump)
        if dump.crc_error:
            await self.link.write_async(self.NACK.encode())
            raise BadCRCException
        return dump

    async def _check_revision(self):
        """Check firmware date and get data format revision."""

        # Rev "A" firmware, dated before April 24, 2002 uses the old format.
        # Rev "B" firmware dated on or after April 24, 2002
        date = datetime(2002, 4, 24).date()
        self.RevA = self.RevB = True
        if await self.firmware_date < date:  # type: ignore  # noqa: PGH003
            self.RevB = False
        else:
            self.RevA = False
