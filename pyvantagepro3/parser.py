"""pyvantagepro2.parser-------------------Allows parsing Vantage Pro2 data."""

from array import array
from datetime import datetime
import logging
import struct

from .utils import Dict, binary_to_int, bytes_to_binary, bytes_to_hex, cached_property

_LOGGER = logging.getLogger(__name__)


class VantageProCRC:
    """Implements CRC algorithm, necessary for encoding and verifying data from the Davis Vantage Pro unit."""

    CRC_TABLE = (
        0x0,
        0x1021,
        0x2042,
        0x3063,
        0x4084,
        0x50A5,
        0x60C6,
        0x70E7,
        0x8108,
        0x9129,
        0xA14A,
        0xB16B,
        0xC18C,
        0xD1AD,
        0xE1CE,
        0xF1EF,
        0x1231,
        0x210,
        0x3273,
        0x2252,
        0x52B5,
        0x4294,
        0x72F7,
        0x62D6,
        0x9339,
        0x8318,
        0xB37B,
        0xA35A,
        0xD3BD,
        0xC39C,
        0xF3FF,
        0xE3DE,
        0x2462,
        0x3443,
        0x420,
        0x1401,
        0x64E6,
        0x74C7,
        0x44A4,
        0x5485,
        0xA56A,
        0xB54B,
        0x8528,
        0x9509,
        0xE5EE,
        0xF5CF,
        0xC5AC,
        0xD58D,
        0x3653,
        0x2672,
        0x1611,
        0x630,
        0x76D7,
        0x66F6,
        0x5695,
        0x46B4,
        0xB75B,
        0xA77A,
        0x9719,
        0x8738,
        0xF7DF,
        0xE7FE,
        0xD79D,
        0xC7BC,
        0x48C4,
        0x58E5,
        0x6886,
        0x78A7,
        0x840,
        0x1861,
        0x2802,
        0x3823,
        0xC9CC,
        0xD9ED,
        0xE98E,
        0xF9AF,
        0x8948,
        0x9969,
        0xA90A,
        0xB92B,
        0x5AF5,
        0x4AD4,
        0x7AB7,
        0x6A96,
        0x1A71,
        0xA50,
        0x3A33,
        0x2A12,
        0xDBFD,
        0xCBDC,
        0xFBBF,
        0xEB9E,
        0x9B79,
        0x8B58,
        0xBB3B,
        0xAB1A,
        0x6CA6,
        0x7C87,
        0x4CE4,
        0x5CC5,
        0x2C22,
        0x3C03,
        0xC60,
        0x1C41,
        0xEDAE,
        0xFD8F,
        0xCDEC,
        0xDDCD,
        0xAD2A,
        0xBD0B,
        0x8D68,
        0x9D49,
        0x7E97,
        0x6EB6,
        0x5ED5,
        0x4EF4,
        0x3E13,
        0x2E32,
        0x1E51,
        0xE70,
        0xFF9F,
        0xEFBE,
        0xDFDD,
        0xCFFC,
        0xBF1B,
        0xAF3A,
        0x9F59,
        0x8F78,
        0x9188,
        0x81A9,
        0xB1CA,
        0xA1EB,
        0xD10C,
        0xC12D,
        0xF14E,
        0xE16F,
        0x1080,
        0xA1,
        0x30C2,
        0x20E3,
        0x5004,
        0x4025,
        0x7046,
        0x6067,
        0x83B9,
        0x9398,
        0xA3FB,
        0xB3DA,
        0xC33D,
        0xD31C,
        0xE37F,
        0xF35E,
        0x2B1,
        0x1290,
        0x22F3,
        0x32D2,
        0x4235,
        0x5214,
        0x6277,
        0x7256,
        0xB5EA,
        0xA5CB,
        0x95A8,
        0x8589,
        0xF56E,
        0xE54F,
        0xD52C,
        0xC50D,
        0x34E2,
        0x24C3,
        0x14A0,
        0x481,
        0x7466,
        0x6447,
        0x5424,
        0x4405,
        0xA7DB,
        0xB7FA,
        0x8799,
        0x97B8,
        0xE75F,
        0xF77E,
        0xC71D,
        0xD73C,
        0x26D3,
        0x36F2,
        0x691,
        0x16B0,
        0x6657,
        0x7676,
        0x4615,
        0x5634,
        0xD94C,
        0xC96D,
        0xF90E,
        0xE92F,
        0x99C8,
        0x89E9,
        0xB98A,
        0xA9AB,
        0x5844,
        0x4865,
        0x7806,
        0x6827,
        0x18C0,
        0x8E1,
        0x3882,
        0x28A3,
        0xCB7D,
        0xDB5C,
        0xEB3F,
        0xFB1E,
        0x8BF9,
        0x9BD8,
        0xABBB,
        0xBB9A,
        0x4A75,
        0x5A54,
        0x6A37,
        0x7A16,
        0xAF1,
        0x1AD0,
        0x2AB3,
        0x3A92,
        0xFD2E,
        0xED0F,
        0xDD6C,
        0xCD4D,
        0xBDAA,
        0xAD8B,
        0x9DE8,
        0x8DC9,
        0x7C26,
        0x6C07,
        0x5C64,
        0x4C45,
        0x3CA2,
        0x2C83,
        0x1CE0,
        0xCC1,
        0xEF1F,
        0xFF3E,
        0xCF5D,
        0xDF7C,
        0xAF9B,
        0xBFBA,
        0x8FD9,
        0x9FF8,
        0x6E17,
        0x7E36,
        0x4E55,
        0x5E74,
        0x2E93,
        0x3EB2,
        0xED1,
        0x1EF0,
    )

    def __init__(self, data) -> None:
        """Initalize."""

        self.data = data

    @cached_property
    def checksum(self):
        """Return CRC calc value from raw serial data."""

        crc = 0
        if isinstance(self.data, bytes):
            for byte in array("B", bytes(self.data)):
                crc = self.CRC_TABLE[((crc >> 8) ^ byte)] ^ ((crc & 0xFF) << 8)
            return crc
        return None

    @cached_property
    def data_with_checksum(self):
        """Return packed raw CRC from raw data."""

        checksum = struct.pack(b">H", self.checksum)
        return b"".join([self.data, checksum])

    def check(self):
        """Perform CRC check on raw serial data, return true if valid.

        A valid CRC == 0.
        """

        if len(self.data) != 0 and self.checksum == 0:
            return True
        return False


class DataParser(Dict):
    """Implements a reusable class for working with a binary data structure. It provides a named fields interface, similiar to C structures."""

    def __init__(self, data, data_format, order="=") -> None:
        """Initalize."""

        super().__init__()
        self.fields, format_t = zip(*data_format, strict=False)
        self.crc_error = False
        if "CRC" in self.fields:
            self.crc_error = not VantageProCRC(data).check()
        format_t = str("{}{}".format(order, "".join(format_t)))
        self.struct = struct.Struct(format=format_t)
        # save raw_bytes
        self.raw_bytes = data
        # Unpacks data from `raw_bytes` and returns a dication of named fields
        data = self.struct.unpack_from(self.raw_bytes, 0)
        self["Datetime"] = None
        self.update(Dict(zip(self.fields, data, strict=False)))

    @cached_property
    def raw(self):
        """Raw daTa."""

        return bytes_to_hex(self.raw_bytes)

    def tuple_to_dict(self, key):
        """Convert {key<->tuple} to {key1<->value2, key2<->value2 ... }."""

        for i, value in enumerate(self[key]):
            self["%s%.2d" % (key, i + 1)] = value  # noqa: UP031
        del self[key]

    def __unicode__(self):
        """Unicode."""

        name = self.__class__.__name__
        return f"<{name} {self.raw}>"

    def __str__(self):
        """Str."""

        return str(self.__unicode__())

    def __repr__(self):
        """Repr."""

        return str(self.__unicode__())


class HiLowParser(Dict):
    """Implements a reusable class for working with a binary data structure. It provides a named fields interface, similiar to C structures."""

    def __init__(self, data, data_format, order="=") -> None:
        """Initalize."""

        super().__init__()
        self.fields, format_t = zip(*data_format, strict=False)
        self.crc_error = False
        if "CRC" in self.fields:
            self.crc_error = not VantageProCRC(data).check()
        format_t = str("{}{}".format(order, "".join(format_t)))
        self.struct = struct.Struct(format=format_t)
        # save raw_bytes
        self.raw_bytes = data
        # Unpacks data from `raw_bytes` and returns a dication of named fields
        data = self.struct.unpack_from(self.raw_bytes, 0)
        self.update(Dict(zip(self.fields, data, strict=False)))

    @cached_property
    def raw(self):
        """Raw data."""

        return bytes_to_hex(self.raw_bytes)

    def tuple_to_dict(self, key):
        """Convert {key<->tuple} to {key1<->value2, key2<->value2 ... }."""

        for i, value in enumerate(self[key]):
            self["%s%.2d" % (key, i + 1)] = value  # noqa: UP031
        del self[key]

    def __unicode__(self):
        """Unicode."""

        name = self.__class__.__name__
        return f"<{name} {self.raw}>"

    def __str__(self):
        """Str."""

        return str(self.__unicode__())

    def __repr__(self):
        """Repr."""

        return str(self.__unicode__())


class LoopDataParserRevB(DataParser):
    """Parse data returned by the 'LOOP' command. It contains all of the real-time data that can be read from the Davis VantagePro2."""

    # Loop data format (RevB)
    LOOP_FORMAT = (
        ("LOO", "3s"),
        ("BarTrend", "B"),
        ("PacketType", "B"),
        ("NextRec", "H"),
        ("Barometer", "H"),
        ("TempIn", "H"),
        ("HumIn", "B"),
        ("TempOut", "H"),
        ("WindSpeed", "B"),
        ("WindSpeed10Min", "B"),
        ("WindDir", "H"),
        ("ExtraTemps", "7s"),
        ("SoilTemps", "4s"),
        ("LeafTemps", "4s"),
        ("HumOut", "B"),
        ("HumExtra", "7s"),
        ("RainRate", "H"),
        ("UV", "B"),
        ("SolarRad", "H"),
        ("RainStorm", "H"),
        ("StormStartDate", "H"),
        ("RainDay", "H"),
        ("RainMonth", "H"),
        ("RainYear", "H"),
        ("ETDay", "H"),
        ("ETMonth", "H"),
        ("ETYear", "H"),
        ("SoilMoist", "4s"),
        ("LeafWetness", "4s"),
        ("AlarmIn", "B"),
        ("AlarmRain", "B"),
        ("AlarmOut", "2s"),
        ("AlarmExTempHum", "8s"),
        ("AlarmSoilLeaf", "4s"),
        ("BatteryStatus", "B"),
        ("BatteryVolts", "H"),
        ("ForecastIcon", "B"),
        ("ForecastRuleNo", "B"),
        ("SunRise", "H"),
        ("SunSet", "H"),
        ("EOL", "2s"),
        ("CRC", "H"),
    )

    def __init__(self, data, dtime) -> None:
        """Initalize."""

        super().__init__(data, self.LOOP_FORMAT)
        self["Datetime"] = dtime
        self["Barometer"] = self["Barometer"] / 1000
        self["TempIn"] = self["TempIn"] / 10
        self["TempOut"] = self["TempOut"] / 10
        self["RainRate"] = self["RainRate"] / 100
        self["RainStorm"] = self["RainStorm"] / 100
        # Given a packed storm date field, unpack and return date
        self["StormStartDate"] = self.unpack_storm_date()
        # rain totals
        self["RainDay"] = self["RainDay"] / 100
        self["RainMonth"] = self["RainMonth"] / 100
        self["RainYear"] = self["RainYear"] / 100
        # evapotranspiration totals
        self["ETDay"] = self["ETDay"] / 1000
        self["ETMonth"] = self["ETMonth"] / 100
        self["ETYear"] = self["ETYear"] / 100
        # battery statistics
        self["BatteryVolts"] = self["BatteryVolts"] * 300 / 512 / 100
        # sunrise / sunset
        self["SunRise"] = self.unpack_time(self["SunRise"])
        self["SunSet"] = self.unpack_time(self["SunSet"])
        # convert to int
        self["HumExtra"] = struct.unpack(b"7B", self["HumExtra"])
        self["ExtraTemps"] = struct.unpack(b"7B", self["ExtraTemps"])
        self["SoilMoist"] = struct.unpack(b"4B", self["SoilMoist"])
        self["SoilTemps"] = struct.unpack(b"4B", self["SoilTemps"])
        self["LeafWetness"] = struct.unpack(b"4B", self["LeafWetness"])
        self["LeafTemps"] = struct.unpack(b"4B", self["LeafTemps"])

        # Inside Alarms bits extraction, only 7 bits are used
        self["AlarmIn"] = bytes_to_binary(self.raw_bytes[70:71])
        self["AlarmInFallBarTrend"] = int(self["AlarmIn"][0])
        self["AlarmInRisBarTrend"] = int(self["AlarmIn"][1])
        self["AlarmInLowTemp"] = int(self["AlarmIn"][2])
        self["AlarmInHighTemp"] = int(self["AlarmIn"][3])
        self["AlarmInLowHum"] = int(self["AlarmIn"][4])
        self["AlarmInHighHum"] = int(self["AlarmIn"][5])
        self["AlarmInTime"] = int(self["AlarmIn"][6])
        del self["AlarmIn"]
        # Rain Alarms bits extraction, only 5 bits are used
        self["AlarmRain"] = bytes_to_binary(self.raw_bytes[71:72])
        self["AlarmRainHighRate"] = int(self["AlarmRain"][0])
        self["AlarmRain15min"] = int(self["AlarmRain"][1])
        self["AlarmRain24hour"] = int(self["AlarmRain"][2])
        self["AlarmRainStormTotal"] = int(self["AlarmRain"][3])
        self["AlarmRainETDaily"] = int(self["AlarmRain"][4])
        del self["AlarmRain"]
        # Oustide Alarms bits extraction, only 13 bits are used
        self["AlarmOut"] = bytes_to_binary(self.raw_bytes[72:73])
        self["AlarmOutLowTemp"] = int(self["AlarmOut"][0])
        self["AlarmOutHighTemp"] = int(self["AlarmOut"][1])
        self["AlarmOutWindSpeed"] = int(self["AlarmOut"][2])
        self["AlarmOut10minAvgSpeed"] = int(self["AlarmOut"][3])
        self["AlarmOutLowDewpoint"] = int(self["AlarmOut"][4])
        self["AlarmOutHighDewPoint"] = int(self["AlarmOut"][5])
        self["AlarmOutHighHeat"] = int(self["AlarmOut"][6])
        self["AlarmOutLowWindChill"] = int(self["AlarmOut"][7])
        self["AlarmOut"] = bytes_to_binary(self.raw_bytes[73])
        self["AlarmOutHighTHSW"] = int(self["AlarmOut"][0])
        self["AlarmOutHighSolarRad"] = int(self["AlarmOut"][1])
        self["AlarmOutHighUV"] = int(self["AlarmOut"][2])
        self["AlarmOutUVDose"] = int(self["AlarmOut"][3])
        self["AlarmOutUVDoseEnabled"] = int(self["AlarmOut"][4])
        del self["AlarmOut"]
        # AlarmExTempHum bits extraction, only 3 bits are used, but 7 bytes
        for i in range(1, 8):
            data = self.raw_bytes[73 + i : 74 + i]
            self["AlarmExTempHum"] = bytes_to_binary(data)
            self["AlarmEx%.2dLowTemp" % i] = int(self["AlarmExTempHum"][0])  # noqa: UP031
            self["AlarmEx%.2dHighTemp" % i] = int(self["AlarmExTempHum"][1])  # noqa: UP031
            self["AlarmEx%.2dLowHum" % i] = int(self["AlarmExTempHum"][2])  # noqa: UP031
            self["AlarmEx%.2dHighHum" % i] = int(self["AlarmExTempHum"][3])  # noqa: UP031
        del self["AlarmExTempHum"]
        # AlarmSoilLeaf 8bits, 4 bytes
        for i in range(1, 5):
            data = self.raw_bytes[81 + i : 82 + i]
            self["AlarmSoilLeaf"] = bytes_to_binary(data)
            self["Alarm%.2dLowLeafWet" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dHighLeafWet" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dLowSoilMois" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dHighSoilMois" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dLowLeafTemp" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dHighLeafTemp" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dLowSoilTemp" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
            self["Alarm%.2dHighSoilTemp" % i] = int(self["AlarmSoilLeaf"][0])  # noqa: UP031
        del self["AlarmSoilLeaf"]
        # delete unused values
        del self["LOO"]
        del self["NextRec"]
        del self["PacketType"]
        del self["EOL"]
        del self["CRC"]
        # Tuple to dict
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("HumExtra")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("SoilMoist")

    def unpack_storm_date(self):
        """Given a packed storm date field, unpack and return date."""

        date = bytes_to_binary(self.raw_bytes[48:50])
        date = date[8:16] + date[0:8]
        year = binary_to_int(date, 0, 7) + 2000
        day = binary_to_int(date, 7, 12)
        month = binary_to_int(date, 12, 16)
        return f"{year}-{month}-{day}"

    def unpack_time(self, time):
        """Given a packed time field, unpack and return "HH:MM" string."""

        # format: HHMM, and space padded on the left.ex: "601" is 6:01 AM
        return "%02d:%02d" % divmod(time, 100)  # covert to "06:01"  # noqa: UP031


class HighLowParserRevB(HiLowParser):
    """Parse data returned by the 'LOOP' command. It contains all of the real-time data that can be read from the Davis VantagePro2."""

    # Loop data format (RevB)
    LOOP_FORMAT = (
        ("DailyLowBarometer", "H"),
        ("DailyHighBarometer", "H"),
        ("MonthlyLowBar", "H"),
        ("MonthlyHighBar", "H"),
        ("YearLowBarometer", "H"),
        ("YearHighBarometer", "H"),
        ("TimeOfDayLowBar", "H"),
        ("TimeOfDayHighBar", "H"),
        ("DailyHighWindSpeed", "B"),
        ("TimeOfHighWindSpeed", "H"),
        ("MonthHighWindSpeed", "B"),
        ("YearHighWindSpeed", "B"),
        ("DayHiInsideTemp", "H"),
        ("DayLowInsideTemp", "H"),
        ("TimeDayHiInTemp", "H"),
        ("TimeDayLowInTemp", "H"),
        ("MonthLowInTemp", "H"),
        ("MonthHiInTemp", "H"),
        ("YearLowInTemp", "H"),
        ("YearHiInTemp", "H"),
        ("DayHiInHum", "B"),
        ("DayLowInHum", "B"),
        ("TimeDayHiInHum", "H"),
        ("TimeDayLowInHum", "H"),
        ("MonthHiInHum", "B"),
        ("MonthLowInHum", "B"),
        ("YearHiInHum", "B"),
        ("YearLowInHum", "B"),
        ("DayLowOutTemp", "H"),
        ("DayHiOutTemp", "H"),
        ("TimeDayLowOutTemp", "H"),
        ("TimeDayHiOutTemp", "H"),
        ("MonthHiOutTemp", "H"),
        ("MonthLowOutTemp", "H"),
        ("YearHiOutTemp", "H"),
        ("YearLowOutTemp", "H"),
        ("DayLowDewPoint", "H"),
        ("DayHiDewPoint", "H"),
        ("TimeDayLowDewPoint", "H"),
        ("TimeDayHiDewPoint", "H"),
        ("MonthHiDewPoint", "H"),
        ("MonthLowDewPoint", "H"),
        ("YearHiDewPoint", "H"),
        ("YearLowDewPoint", "H"),
        ("DayLowWindChill", "H"),
        ("TimeDayLowChill", "H"),
        ("MonthLowWindChill", "H"),
        ("YearLowWindChill", "H"),
        ("DayHighHeat", "H"),
        ("TimeofDayHighHeat", "H"),
        ("MonthHighHeat", "H"),
        ("YearHighHeat", "H"),
        ("DayHighTHSW", "H"),
        ("TimeofDayHighTHSW", "H"),
        ("MonthHighTHSW", "H"),
        ("YearHighTHSW", "H"),
        ("DayHighSolarRad", "H"),
        ("TimeofDayHighSolar", "H"),
        ("MonthHighSolarRad", "H"),
        ("YearHighSolarRad", "H"),
        ("DayHighUV", "B"),
        ("TimeofDayHighUV", "H"),
        ("MonthHighUV", "B"),
        ("YearHighUV", "B"),
        ("DayHighRainRate", "H"),
        ("TimeofDayHighRainRate", "H"),
        ("HourHighRainRate", "H"),
        ("MonthHighRainRate", "H"),
        ("YearHighRainRate", "H"),
        ("DayLowTempExtraTemp2", "B"),
        ("DayLowTempExtraTemp3", "B"),
        ("DayLowTempExtraTemp4", "B"),
        ("DayLowTempExtraTemp5", "B"),
        ("DayLowTempExtraTemp6", "B"),
        ("DayLowTempExtraTemp7", "B"),
        ("DayLowTempExtraTemp8", "B"),
        ("DayLowTempSoil1", "B"),
        ("DayLowTempSoil2", "B"),
        ("DayLowTempSoil3", "B"),
        ("DayLowTempSoil4", "B"),
        ("DayLowTempLeaf1", "B"),
        ("DayLowTempLeaf2", "B"),
        ("DayLowTempLeaf3", "B"),
        ("DayLowTempLeaf4", "B"),
        ("DayHiTemperature", "B"),
        ("TimeDayLowTempExtraTemp2", "H"),
        ("TimeDayLowTempExtraTemp3", "H"),
        ("TimeDayLowTempExtraTemp4", "H"),
        ("TimeDayLowTempExtraTemp5", "H"),
        ("TimeDayLowTempExtraTemp6", "H"),
        ("TimeDayLowTempExtraTemp7", "H"),
        ("TimeDayLowTempExtraTemp8", "H"),
        ("TimeDayLowTempSoil1", "H"),
        ("TimeDayLowTempSoil2", "H"),
        ("TimeDayLowTempSoil3", "H"),
        ("TimeDayLowTempSoil4", "H"),
        ("TimeDayLowTempLeaf1", "H"),
        ("TimeDayLowTempLeaf2", "H"),
        ("TimeDayLowTempLeaf3", "H"),
        ("TimeDayLowTempLeaf4", "H"),
        ("TimeDayHiTempExtraTemp2", "H"),
        ("TimeDayHiTempExtraTemp3", "H"),
        ("TimeDayHiTempExtraTemp4", "H"),
        ("TimeDayHiTempExtraTemp5", "H"),
        ("TimeDayHiTempExtraTemp6", "H"),
        ("TimeDayHiTempExtraTemp7", "H"),
        ("TimeDayHiTempExtraTemp8", "H"),
        ("TimeDayHiTempSoil1", "H"),
        ("TimeDayHiTempSoil2", "H"),
        ("TimeDayHiTempSoil3", "H"),
        ("TimeDayHiTempSoil4", "H"),
        ("TimeDayHiTempLeaf1", "H"),
        ("TimeDayHiTempLeaf2", "H"),
        ("TimeDayHiTempLeaf3", "H"),
        ("TimeDayHiTempLeaf4", "H"),
        ("MonthHiTempExtraTemp2", "B"),
        ("MonthHiTempExtraTemp3", "B"),
        ("MonthHiTempExtraTemp4", "B"),
        ("MonthHiTempExtraTemp5", "B"),
        ("MonthHiTempExtraTemp6", "B"),
        ("MonthHiTempExtraTemp7", "B"),
        ("MonthHiTempExtraTemp8", "B"),
        ("MonthHiTempSoil1", "B"),
        ("MonthHiTempSoil2", "B"),
        ("MonthHiTempSoil3", "B"),
        ("MonthHiTempSoil4", "B"),
        ("MonthHiTempLeaf1", "B"),
        ("MonthHiTempLeaf2", "B"),
        ("MonthHiTempLeaf3", "B"),
        ("MonthHiTempLeaf4", "B"),
        ("MonthLowTempExtraTemp2", "B"),
        ("MonthLowTempExtraTemp3", "B"),
        ("MonthLowTempExtraTemp4", "B"),
        ("MonthLowTempExtraTemp5", "B"),
        ("MonthLowTempExtraTemp6", "B"),
        ("MonthLowTempExtraTemp7", "B"),
        ("MonthLowTempExtraTemp8", "B"),
        ("MonthLowTempSoil1", "B"),
        ("MonthLowTempSoil2", "B"),
        ("MonthLowTempSoil3", "B"),
        ("MonthLowTempSoil4", "B"),
        ("MonthLowTempLeaf1", "B"),
        ("MonthLowTempLeaf2", "B"),
        ("MonthLowTempLeaf3", "B"),
        ("MonthLowTempLeaf4", "B"),
        ("YearHiTempExtraTemp2", "B"),
        ("YearHiTempExtraTemp3", "B"),
        ("YearHiTempExtraTemp4", "B"),
        ("YearHiTempExtraTemp5", "B"),
        ("YearHiTempExtraTemp6", "B"),
        ("YearHiTempExtraTemp7", "B"),
        ("YearHiTempExtraTemp8", "B"),
        ("YearHiTempSoil1", "B"),
        ("YearHiTempSoil2", "B"),
        ("YearHiTempSoil3", "B"),
        ("YearHiTempSoil4", "B"),
        ("YearHiTempLeaf1", "B"),
        ("YearHiTempLeaf2", "B"),
        ("YearHiTempLeaf3", "B"),
        ("YearHiTempLeaf4", "B"),
        ("YearLowTempExtraTemp2", "B"),
        ("YearLowTempExtraTemp3", "B"),
        ("YearLowTempExtraTemp4", "B"),
        ("YearLowTempExtraTemp5", "B"),
        ("YearLowTempExtraTemp6", "B"),
        ("YearLowTempExtraTemp7", "B"),
        ("YearLowTempExtraTemp8", "B"),
        ("YearLowTempSoil1", "B"),
        ("YearLowTempSoil2", "B"),
        ("YearLowTempSoil3", "B"),
        ("YearLowTempSoil4", "B"),
        ("YearLowTempLeaf1", "B"),
        ("YearLowTempLeaf2", "B"),
        ("YearLowTempLeaf3", "B"),
        ("YearLowTempLeaf4", "B"),
        ("DayLowOutHum", "B"),
        ("DayLowOutExtraHum2", "B"),
        ("DayLowOutExtraHum3", "B"),
        ("DayLowOutExtraHum4", "B"),
        ("DayLowOutExtraHum5", "B"),
        ("DayLowOutExtraHum6", "B"),
        ("DayLowOutExtraHum7", "B"),
        ("DayLowOutExtraHum8", "B"),
        ("DayHiOutHum", "B"),
        ("DayHiOutExtraHum2", "B"),
        ("DayHiOutExtraHum3", "B"),
        ("DayHiOutExtraHum4", "B"),
        ("DayHiOutExtraHum5", "B"),
        ("DayHiOutExtraHum6", "B"),
        ("DayHiOutExtraHum7", "B"),
        ("DayHiOutExtraHum8", "B"),
        ("TimeDayLowOutHum", "H"),
        ("TimeDayLowOutExtraHum2", "H"),
        ("TimeDayLowOutExtraHum3", "H"),
        ("TimeDayLowOutExtraHum4", "H"),
        ("TimeDayLowOutExtraHum5", "H"),
        ("TimeDayLowOutExtraHum6", "H"),
        ("TimeDayLowOutExtraHum7", "H"),
        ("TimeDayLowOutExtraHum8", "H"),
        ("TimeDayHiOutHum", "H"),
        ("TimeDayHiOutExtraHum2", "H"),
        ("TimeDayHiOutExtraHum3", "H"),
        ("TimeDayHiOutExtraHum4", "H"),
        ("TimeDayHiOutExtraHum5", "H"),
        ("TimeDayHiOutExtraHum6", "H"),
        ("TimeDayHiOutExtraHum7", "H"),
        ("TimeDayHiOutExtraHum8", "H"),
        ("MonthHiOutHum", "B"),
        ("MonthHiOutExtraHum2", "B"),
        ("MonthHiOutExtraHum3", "B"),
        ("MonthHiOutExtraHum4", "B"),
        ("MonthHiOutExtraHum5", "B"),
        ("MonthHiOutExtraHum6", "B"),
        ("MonthHiOutExtraHum7", "B"),
        ("MonthHiOutExtraHum8", "B"),
        ("MonthLowOutHum", "B"),
        ("MonthLowOutExtraHum2", "B"),
        ("MonthLowOutExtraHum3", "B"),
        ("MonthLowOutExtraHum4", "B"),
        ("MonthLowOutExtraHum5", "B"),
        ("MonthLowOutExtraHum6", "B"),
        ("MonthLowOutExtraHum7", "B"),
        ("MonthLowOutExtraHum8", "B"),
        ("YearHiOutHum", "B"),
        ("YearHiOutExtraHum2", "B"),
        ("YearHiOutExtraHum3", "B"),
        ("YearHiOutExtraHum4", "B"),
        ("YearHiOutExtraHum5", "B"),
        ("YearHiOutExtraHum6", "B"),
        ("YearHiOutExtraHum7", "B"),
        ("YearHiOutExtraHum8", "B"),
        ("YearLowOutHum", "B"),
        ("YearLowOutExtraHum2", "B"),
        ("YearLowOutExtraHum3", "B"),
        ("YearLowOutExtraHum4", "B"),
        ("YearLowOutExtraHum5", "B"),
        ("YearLowOutExtraHum6", "B"),
        ("YearLowOutExtraHum7", "B"),
        ("YearLowOutExtraHum8", "B"),
        ("DayHiSoilMoisture1", "B"),
        ("DayHiSoilMoisture2", "B"),
        ("DayHiSoilMoisture3", "B"),
        ("DayHiSoilMoisture4", "B"),
        ("TimeDayHiSoilMoisture1", "H"),
        ("TimeDayHiSoilMoisture2", "H"),
        ("TimeDayHiSoilMoisture3", "H"),
        ("TimeDayHiSoilMoisture4", "H"),
        ("DayLowSoilMoisture1", "B"),
        ("DayLowSoilMoisture2", "B"),
        ("DayLowSoilMoisture3", "B"),
        ("DayLowSoilMoisture4", "B"),
        ("TimeDayLowSoilMoisture1", "H"),
        ("TimeDayLowSoilMoisture2", "H"),
        ("TimeDayLowSoilMoisture3", "H"),
        ("TimeDayLowSoilMoisture4", "H"),
        ("MonthLowSoilMoisture1", "B"),
        ("MonthLowSoilMoisture2", "B"),
        ("MonthLowSoilMoisture3", "B"),
        ("MonthLowSoilMoisture4", "B"),
        ("MonthHiSoilMoisture1", "B"),
        ("MonthHiSoilMoisture2", "B"),
        ("MonthHiSoilMoisture3", "B"),
        ("MonthHiSoilMoisture4", "B"),
        ("YearLowSoilMoisture1", "B"),
        ("YearLowSoilMoisture2", "B"),
        ("YearLowSoilMoisture3", "B"),
        ("YearLowSoilMoisture4", "B"),
        ("YearHiSoilMoisture1", "B"),
        ("YearHiSoilMoisture2", "B"),
        ("YearHiSoilMoisture3", "B"),
        ("YearHiSoilMoisture4", "B"),
        ("DayHiLeafWetness1", "B"),
        ("DayHiLeafWetness2", "B"),
        ("DayHiLeafWetness3", "B"),
        ("DayHiLeafWetness4", "B"),
        ("TimeDayHiLeafWetness1", "H"),
        ("TimeDayHiLeafWetness2", "H"),
        ("TimeDayHiLeafWetness3", "H"),
        ("TimeDayHiLeafWetness4", "H"),
        ("DayLowLeafWetness1", "B"),
        ("DayLowLeafWetness2", "B"),
        ("DayLowLeafWetness3", "B"),
        ("DayLowLeafWetness4", "B"),
        ("TimeDayLowLeafWetness1", "H"),
        ("TimeDayLowLeafWetness2", "H"),
        ("TimeDayLowLeafWetness3", "H"),
        ("TimeDayLowLeafWetness4", "H"),
        ("MonthLowLeafWetness1", "B"),
        ("MonthLowLeafWetness2", "B"),
        ("MonthLowLeafWetness3", "B"),
        ("MonthLowLeafWetness4", "B"),
        ("MonthHiLeafWetness1", "B"),
        ("MonthHiLeafWetness2", "B"),
        ("MonthHiLeafWetness3", "B"),
        ("MonthHiLeafWetness4", "B"),
        ("YearLowLeafWetness1", "B"),
        ("YearLowLeafWetness2", "B"),
        ("YearLowLeafWetness3", "B"),
        ("YearLowLeafWetness4", "B"),
        ("YearHiLeafWetness1", "B"),
        ("YearHiLeafWetness2", "B"),
        ("YearHiLeafWetness3", "B"),
        ("YearHiLeafWetness4", "B"),
    )

    def __init__(self, data) -> None:
        """Initalize."""

    def __init__(self, data) -> None:
        """Initalize."""

        super().__init__(data, self.LOOP_FORMAT)
        self["DailyLowBarometer"] = self["DailyLowBarometer"] / 1000
        self["DailyHighBarometer"] = self["DailyHighBarometer"] / 1000
        self["MonthlyLowBar"] = self["MonthlyLowBar"] / 1000
        self["MonthlyHighBar"] = self["MonthlyHighBar"] / 1000
        self["YearLowBarometer"] = self["YearLowBarometer"] / 1000
        self["YearHighBarometer"] = self["YearHighBarometer"] / 1000
        self["TimeOfDayLowBar"] = self.unpack_time(self["TimeOfDayLowBar"])
        self["TimeOfDayHighBar"] = self.unpack_time(self["TimeOfDayHighBar"])
        self["TimeOfHighWindSpeed"] = self.unpack_time(self["TimeOfHighWindSpeed"])
        self["DayHiInsideTemp"] = self["DayHiInsideTemp"] / 10
        self["DayLowInsideTemp"] = self["DayLowInsideTemp"] / 10
        self["TimeDayHiInTemp"] = self.unpack_time(self["TimeDayHiInTemp"])
        self["TimeDayLowInTemp"] = self.unpack_time(self["TimeDayLowInTemp"])
        self["MonthLowInTemp"] = self["MonthLowInTemp"] / 10
        self["MonthHiInTemp"] = self["MonthHiInTemp"] / 10
        self["YearLowInTemp"] = self["YearLowInTemp"] / 10
        self["YearHiInTemp"] = self["YearHiInTemp"] / 10
        self["TimeDayHiInHum"] = self.unpack_time(self["TimeDayHiInHum"])
        self["TimeDayLowInHum"] = self.unpack_time(self["TimeDayLowInHum"])
        self["DayLowOutTemp"] = self["DayLowOutTemp"] / 10
        self["DayHiOutTemp"] = self["DayHiOutTemp"] / 10
        self["TimeDayLowOutTemp"] = self.unpack_time(self["TimeDayLowOutTemp"])
        self["TimeDayHiOutTemp"] = self.unpack_time(self["TimeDayHiOutTemp"])
        self["MonthHiOutTemp"] = self["MonthHiOutTemp"] / 10
        self["MonthLowOutTemp"] = self["MonthLowOutTemp"] / 10
        self["YearHiOutTemp"] = self["YearHiOutTemp"] / 10
        self["YearLowOutTemp"] = self["YearLowOutTemp"] / 10
        self["TimeDayLowDewPoint"] = self.unpack_time(self["TimeDayLowDewPoint"])
        self["TimeDayHiDewPoint"] = self.unpack_time(self["TimeDayHiDewPoint"])
        self["TimeDayLowChill"] = self.unpack_time(self["TimeDayLowChill"])
        self["TimeofDayHighHeat"] = self.unpack_time(self["TimeofDayHighHeat"])
        self["TimeofDayHighTHSW"] = self.unpack_time(self["TimeofDayHighTHSW"])
        self["TimeofDayHighSolar"] = self.unpack_time(self["TimeofDayHighSolar"])
        self["TimeofDayHighUV"] = self.unpack_time(self["TimeofDayHighUV"])
        self["DayHighRainRate"] = self["DayHighRainRate"] / 100
        self["TimeofDayHighRainRate"] = self.unpack_time(self["TimeofDayHighRainRate"])
        self["HourHighRainRate"] = self["HourHighRainRate"] / 100
        self["MonthHighRainRate"] = self["MonthHighRainRate"] / 100
        self["YearHighRainRate"] = self["YearHighRainRate"] / 100
        self["DayLowTempExtraTemp2"] = self["DayLowTempExtraTemp2"] / 10
        self["DayLowTempExtraTemp3"] = self["DayLowTempExtraTemp3"] / 10
        self["DayLowTempExtraTemp4"] = self["DayLowTempExtraTemp4"] / 10
        self["DayLowTempExtraTemp5"] = self["DayLowTempExtraTemp5"] / 10
        self["DayLowTempExtraTemp6"] = self["DayLowTempExtraTemp6"] / 10
        self["DayLowTempExtraTemp7"] = self["DayLowTempExtraTemp7"] / 10
        self["DayLowTempExtraTemp8"] = self["DayLowTempExtraTemp8"] / 10
        self["DayLowTempSoil1"] = self["DayLowTempSoil1"] / 10
        self["DayLowTempSoil2"] = self["DayLowTempSoil2"] / 10
        self["DayLowTempSoil3"] = self["DayLowTempSoil3"] / 10
        self["DayLowTempSoil4"] = self["DayLowTempSoil4"] / 10
        self["DayLowTempLeaf1"] = self["DayLowTempLeaf1"] / 10
        self["DayLowTempLeaf2"] = self["DayLowTempLeaf2"] / 10
        self["DayLowTempLeaf3"] = self["DayLowTempLeaf3"] / 10
        self["DayLowTempLeaf4"] = self["DayLowTempLeaf4"] / 10
        self["DayHiTemperature"] = self["DayHiTemperature"] / 10
        self["TimeDayLowTempExtraTemp2"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp2"]
        )
        self["TimeDayLowTempExtraTemp3"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp3"]
        )
        self["TimeDayLowTempExtraTemp4"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp4"]
        )
        self["TimeDayLowTempExtraTemp5"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp5"]
        )
        self["TimeDayLowTempExtraTemp6"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp6"]
        )
        self["TimeDayLowTempExtraTemp7"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp7"]
        )
        self["TimeDayLowTempExtraTemp8"] = self.unpack_time(
            self["TimeDayLowTempExtraTemp8"]
        )
        self["TimeDayLowTempSoil1"] = self.unpack_time(self["TimeDayLowTempSoil1"])
        self["TimeDayLowTempSoil2"] = self.unpack_time(self["TimeDayLowTempSoil2"])
        self["TimeDayLowTempSoil3"] = self.unpack_time(self["TimeDayLowTempSoil3"])
        self["TimeDayLowTempSoil4"] = self.unpack_time(self["TimeDayLowTempSoil4"])
        self["TimeDayLowTempLeaf1"] = self.unpack_time(self["TimeDayLowTempLeaf1"])
        self["TimeDayLowTempLeaf2"] = self.unpack_time(self["TimeDayLowTempLeaf2"])
        self["TimeDayLowTempLeaf3"] = self.unpack_time(self["TimeDayLowTempLeaf3"])
        self["TimeDayLowTempLeaf4"] = self.unpack_time(self["TimeDayLowTempLeaf4"])
        self["TimeDayHiTempExtraTemp2"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp2"]
        )
        self["TimeDayHiTempExtraTemp3"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp3"]
        )
        self["TimeDayHiTempExtraTemp4"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp4"]
        )
        self["TimeDayHiTempExtraTemp5"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp5"]
        )
        self["TimeDayHiTempExtraTemp6"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp6"]
        )
        self["TimeDayHiTempExtraTemp7"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp7"]
        )
        self["TimeDayHiTempExtraTemp8"] = self.unpack_time(
            self["TimeDayHiTempExtraTemp8"]
        )
        self["TimeDayHiTempSoil1"] = self.unpack_time(self["TimeDayHiTempSoil1"])
        self["TimeDayHiTempSoil2"] = self.unpack_time(self["TimeDayHiTempSoil2"])
        self["TimeDayHiTempSoil3"] = self.unpack_time(self["TimeDayHiTempSoil3"])
        self["TimeDayHiTempSoil4"] = self.unpack_time(self["TimeDayHiTempSoil4"])
        self["TimeDayHiTempLeaf1"] = self.unpack_time(self["TimeDayHiTempLeaf1"])
        self["TimeDayHiTempLeaf2"] = self.unpack_time(self["TimeDayHiTempLeaf2"])
        self["TimeDayHiTempLeaf3"] = self.unpack_time(self["TimeDayHiTempLeaf3"])
        self["TimeDayHiTempLeaf4"] = self.unpack_time(self["TimeDayHiTempLeaf4"])
        self["MonthHiTempExtraTemp2"] = self["MonthHiTempExtraTemp2"] / 10
        self["MonthHiTempExtraTemp3"] = self["MonthHiTempExtraTemp3"] / 10
        self["MonthHiTempExtraTemp4"] = self["MonthHiTempExtraTemp4"] / 10
        self["MonthHiTempExtraTemp5"] = self["MonthHiTempExtraTemp5"] / 10
        self["MonthHiTempExtraTemp6"] = self["MonthHiTempExtraTemp6"] / 10
        self["MonthHiTempExtraTemp7"] = self["MonthHiTempExtraTemp7"] / 10
        self["MonthHiTempExtraTemp8"] = self["MonthHiTempExtraTemp8"] / 10
        self["MonthHiTempSoil1"] = self["MonthHiTempSoil1"] / 10
        self["MonthHiTempSoil2"] = self["MonthHiTempSoil2"] / 10
        self["MonthHiTempSoil3"] = self["MonthHiTempSoil3"] / 10
        self["MonthHiTempSoil4"] = self["MonthHiTempSoil4"] / 10
        self["MonthHiTempLeaf1"] = self["MonthHiTempLeaf1"] / 10
        self["MonthHiTempLeaf2"] = self["MonthHiTempLeaf2"] / 10
        self["MonthHiTempLeaf3"] = self["MonthHiTempLeaf3"] / 10
        self["MonthHiTempLeaf4"] = self["MonthHiTempLeaf4"] / 10
        self["MonthLowTempExtraTemp2"] = self["MonthLowTempExtraTemp2"] / 10
        self["MonthLowTempExtraTemp3"] = self["MonthLowTempExtraTemp3"] / 10
        self["MonthLowTempExtraTemp4"] = self["MonthLowTempExtraTemp4"] / 10
        self["MonthLowTempExtraTemp5"] = self["MonthLowTempExtraTemp5"] / 10
        self["MonthLowTempExtraTemp6"] = self["MonthLowTempExtraTemp6"] / 10
        self["MonthLowTempExtraTemp7"] = self["MonthLowTempExtraTemp7"] / 10
        self["MonthLowTempExtraTemp8"] = self["MonthLowTempExtraTemp8"] / 10
        self["MonthLowTempSoil1"] = self["MonthLowTempSoil1"] / 10
        self["MonthLowTempSoil2"] = self["MonthLowTempSoil2"] / 10
        self["MonthLowTempSoil3"] = self["MonthLowTempSoil3"] / 10
        self["MonthLowTempSoil4"] = self["MonthLowTempSoil4"] / 10
        self["MonthLowTempLeaf1"] = self["MonthLowTempLeaf1"] / 10
        self["MonthLowTempLeaf2"] = self["MonthLowTempLeaf2"] / 10
        self["MonthLowTempLeaf3"] = self["MonthLowTempLeaf3"] / 10
        self["MonthLowTempLeaf4"] = self["MonthLowTempLeaf4"] / 10
        self["YearHiTempExtraTemp2"] = self["YearHiTempExtraTemp2"] / 10
        self["YearHiTempExtraTemp3"] = self["YearHiTempExtraTemp3"] / 10
        self["YearHiTempExtraTemp4"] = self["YearHiTempExtraTemp4"] / 10
        self["YearHiTempExtraTemp5"] = self["YearHiTempExtraTemp5"] / 10
        self["YearHiTempExtraTemp6"] = self["YearHiTempExtraTemp6"] / 10
        self["YearHiTempExtraTemp7"] = self["YearHiTempExtraTemp7"] / 10
        self["YearHiTempExtraTemp8"] = self["YearHiTempExtraTemp8"] / 10
        self["YearHiTempSoil1"] = self["YearHiTempSoil1"] / 10
        self["YearHiTempSoil2"] = self["YearHiTempSoil2"] / 10
        self["YearHiTempSoil3"] = self["YearHiTempSoil3"] / 10
        self["YearHiTempSoil4"] = self["YearHiTempSoil4"] / 10
        self["YearHiTempLeaf1"] = self["YearHiTempLeaf1"] / 10
        self["YearHiTempLeaf2"] = self["YearHiTempLeaf2"] / 10
        self["YearHiTempLeaf3"] = self["YearHiTempLeaf3"] / 10
        self["YearHiTempLeaf4"] = self["YearHiTempLeaf4"] / 10
        self["YearLowTempExtraTemp2"] = self["YearLowTempExtraTemp2"] / 10
        self["YearLowTempExtraTemp3"] = self["YearLowTempExtraTemp3"] / 10
        self["YearLowTempExtraTemp4"] = self["YearLowTempExtraTemp4"] / 10
        self["YearLowTempExtraTemp5"] = self["YearLowTempExtraTemp5"] / 10
        self["YearLowTempExtraTemp6"] = self["YearLowTempExtraTemp6"] / 10
        self["YearLowTempExtraTemp7"] = self["YearLowTempExtraTemp7"] / 10
        self["YearLowTempExtraTemp8"] = self["YearLowTempExtraTemp8"] / 10
        self["YearLowTempSoil1"] = self["YearLowTempSoil1"] / 10
        self["YearLowTempSoil2"] = self["YearLowTempSoil2"] / 10
        self["YearLowTempSoil3"] = self["YearLowTempSoil3"] / 10
        self["YearLowTempSoil4"] = self["YearLowTempSoil4"] / 10
        self["YearLowTempLeaf1"] = self["YearLowTempLeaf1"] / 10
        self["YearLowTempLeaf2"] = self["YearLowTempLeaf2"] / 10
        self["YearLowTempLeaf3"] = self["YearLowTempLeaf3"] / 10
        self["YearLowTempLeaf4"] = self["YearLowTempLeaf4"] / 10
        self["TimeDayLowOutHum"] = self.unpack_time(self["TimeDayLowOutHum"])
        self["TimeDayLowOutExtraHum2"] = self.unpack_time(
            self["TimeDayLowOutExtraHum2"]
        )
        self["TimeDayLowOutExtraHum3"] = self.unpack_time(
            self["TimeDayLowOutExtraHum3"]
        )
        self["TimeDayLowOutExtraHum4"] = self.unpack_time(
            self["TimeDayLowOutExtraHum4"]
        )
        self["TimeDayLowOutExtraHum5"] = self.unpack_time(
            self["TimeDayLowOutExtraHum5"]
        )
        self["TimeDayLowOutExtraHum6"] = self.unpack_time(
            self["TimeDayLowOutExtraHum6"]
        )
        self["TimeDayLowOutExtraHum7"] = self.unpack_time(
            self["TimeDayLowOutExtraHum7"]
        )
        self["TimeDayLowOutExtraHum8"] = self.unpack_time(
            self["TimeDayLowOutExtraHum8"]
        )
        self["TimeDayHiOutHum"] = self.unpack_time(self["TimeDayHiOutHum"])
        self["TimeDayHiOutExtraHum2"] = self.unpack_time(self["TimeDayHiOutExtraHum2"])
        self["TimeDayHiOutExtraHum3"] = self.unpack_time(self["TimeDayHiOutExtraHum3"])
        self["TimeDayHiOutExtraHum4"] = self.unpack_time(self["TimeDayHiOutExtraHum4"])
        self["TimeDayHiOutExtraHum5"] = self.unpack_time(self["TimeDayHiOutExtraHum5"])
        self["TimeDayHiOutExtraHum6"] = self.unpack_time(self["TimeDayHiOutExtraHum6"])
        self["TimeDayHiOutExtraHum7"] = self.unpack_time(self["TimeDayHiOutExtraHum7"])
        self["TimeDayHiOutExtraHum8"] = self.unpack_time(self["TimeDayHiOutExtraHum8"])

    def unpack_time(self, time):
        """Given a packed time field, unpack and return "HH:MM" string."""

        # format: HHMM, and space padded on the left.ex: "601" is 6:01 AM
        return "%02d:%02d" % divmod(time, 100)  # covert to "06:01"  # noqa: UP031

    def unpack_storm_date(self):
        """Given a packed storm date field, unpack and return date."""

        date = bytes_to_binary(self.raw_bytes[48:50])
        date = date[8:16] + date[0:8]
        year = binary_to_int(date, 0, 7) + 2000
        day = binary_to_int(date, 7, 12)
        month = binary_to_int(date, 12, 16)
        return f"{year}-{month}-{day}"
    
class ArchiveDataParserRevB(DataParser):
    """Parse data returned by the 'LOOP' command. It contains all of the real-time data that can be read from the Davis VantagePro2."""

    ARCHIVE_FORMAT = (
        ("DateStamp", "H"),
        ("TimeStamp", "H"),
        ("TempOut", "H"),
        ("TempOutHi", "H"),
        ("TempOutLow", "H"),
        ("RainRate", "H"),
        ("RainRateHi", "H"),
        ("Barometer", "H"),
        ("SolarRad", "H"),
        ("WindSamps", "H"),
        ("TempIn", "H"),
        ("HumIn", "B"),
        ("HumOut", "B"),
        ("WindAvg", "B"),
        ("WindHi", "B"),
        ("WindHiDir", "B"),
        ("WindAvgDir", "B"),
        ("UV", "B"),
        ("ETHour", "B"),
        ("SolarRadHi", "H"),
        ("UVHi", "B"),
        ("ForecastRuleNo", "B"),
        ("LeafTemps", "2s"),
        ("LeafWetness", "2s"),
        ("SoilTemps", "4s"),
        ("RecType", "B"),
        ("ExtraHum", "2s"),
        ("ExtraTemps", "3s"),
        ("SoilMoist", "4s"),
    )

    def __init__(self, data) -> None:
        """Initalize."""

        super().__init__(data, self.ARCHIVE_FORMAT)
        self["raw_datestamp"] = bytes_to_binary(self.raw_bytes[0:4])
        self["Datetime"] = unpack_dmp_date_time(self["DateStamp"], self["TimeStamp"])
        del self["DateStamp"]
        del self["TimeStamp"]
        self["TempOut"] = self["TempOut"] / 10
        self["TempOutHi"] = self["TempOutHi"] / 10
        self["TempOutLow"] = self["TempOutLow"] / 10
        self["Barometer"] = self["Barometer"] / 1000
        self["TempIn"] = self["TempIn"] / 10
        self["UV"] = self["UV"] / 10
        self["ETHour"] = self["ETHour"] / 1000
        SoilTempsValues = struct.unpack(b"4B", self["SoilTemps"])
        self["SoilTemps"] = tuple((t - 90) for t in SoilTempsValues)
        self["ExtraHum"] = struct.unpack(b"2B", self["ExtraHum"])
        self["SoilMoist"] = struct.unpack(b"4B", self["SoilMoist"])
        LeafTempsValues = struct.unpack(b"2B", self["LeafTemps"])
        self["LeafTemps"] = tuple((t - 90) for t in LeafTempsValues)
        self["LeafWetness"] = struct.unpack(b"2B", self["LeafWetness"])
        ExtraTempsValues = struct.unpack(b"3B", self["ExtraTemps"])
        self["ExtraTemps"] = tuple((t - 90) for t in ExtraTempsValues)
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("SoilMoist")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("ExtraHum")


class DmpHeaderParser(DataParser):
    """Dump Header Parser."""

    DMP_FORMAT = (
        ("Pages", "H"),
        ("Offset", "H"),
        ("CRC", "H"),
    )

    def __init__(self, data) -> None:
        """Initalize."""

        super().__init__(data, self.DMP_FORMAT)


class DmpPageParser(DataParser):
    """Dump Page Parser."""

    DMP_FORMAT = (
        ("Index", "B"),
        ("Records", "260s"),
        ("unused", "4B"),
        ("CRC", "H"),
    )

    def __init__(self, data) -> None:
        """Initalize."""

        super().__init__(data, self.DMP_FORMAT)


def pack_dmp_date_time(d):
    """Pack `datetime` to DateStamp and TimeStamp VantagePro2 with CRC."""
    vpdate = d.day + d.month * 32 + (d.year - 2000) * 512
    vptime = 100 * d.hour + d.minute
    data = struct.pack(b"HH", vpdate, vptime)
    return VantageProCRC(data).data_with_checksum


def unpack_dmp_date_time(date, time):
    """Unpack `date` and `time` to datetime."""

    if date != 0xFFFF and time != 0xFFFF:
        day = date & 0x1F  # 5 bits
        month = (date >> 5) & 0x0F  # 4 bits
        year = ((date >> 9) & 0x7F) + 2000  # 7 bits
        hour, min_ = divmod(time, 100)
        return datetime(year, month, day, hour, min_)
    return None


def pack_datetime(dtime):
    """Returns packed `dtime` with CRC."""

    data = struct.pack(
        b">BBBBBB",
        dtime.second,
        dtime.minute,
        dtime.hour,
        dtime.day,
        dtime.month,
        dtime.year - 1900,
    )
    return VantageProCRC(data).data_with_checksum


def unpack_datetime(data):
    """Return unpacked datetime `data` and check CRC."""

    VantageProCRC(data).check()
    s, m, h, day, month, year = struct.unpack(b">BBBBBB", data[:6])
    return datetime(year + 1900, month, day, h, m, s)







