"""
pyvantagepro2.parser
-------------------

Allows parsing Vantage Pro2 data.


"""

from __future__ import division, unicode_literals
import struct
from datetime import datetime
from array import array

from .compat import bytes
from .logger import LOGGER
from .utils import cached_property, bytes_to_hex, Dict, bytes_to_binary, binary_to_int


class VantageProCRC(object):
    """Implements CRC algorithm, necessary for encoding and verifying data from
    the Davis Vantage Pro unit."""

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

    def __init__(self, data):
        self.data = data

    @cached_property
    def checksum(self):
        """Return CRC calc value from raw serial data."""
        crc = 0
        if isinstance(self.data, bytes):
            for byte in array(str("B"), bytes(self.data)):
                crc = self.CRC_TABLE[((crc >> 8) ^ byte)] ^ ((crc & 0xFF) << 8)
            return crc

    @cached_property
    def data_with_checksum(self):
        """Return packed raw CRC from raw data."""
        checksum = struct.pack(b">H", self.checksum)
        return b"".join([self.data, checksum])

    def check(self):
        """Perform CRC check on raw serial data, return true if valid.
        A valid CRC == 0."""
        if len(self.data) != 0 and self.checksum == 0:
            #            LOGGER.info("Check CRC : OK")
            return True
        else:
            #            LOGGER.error("Check CRC : BAD")
            return False


class DataParser(Dict):
    """Implements a reusable class for working with a binary data structure.
    It provides a named fields interface, similiar to C structures."""

    def __init__(self, data, data_format, order="="):
        super(DataParser, self).__init__()
        self.fields, format_t = zip(*data_format)
        self.crc_error = False
        if "CRC" in self.fields:
            self.crc_error = not VantageProCRC(data).check()
        format_t = str("%s%s" % (order, "".join(format_t)))
        self.struct = struct.Struct(format=format_t)
        # save raw_bytes
        self.raw_bytes = data
        # Unpacks data from `raw_bytes` and returns a dication of named fields
        data = self.struct.unpack_from(self.raw_bytes, 0)
        self["Datetime"] = None
        self.update(Dict(zip(self.fields, data)))

    @cached_property
    def raw(self):
        return bytes_to_hex(self.raw_bytes)

    def tuple_to_dict(self, key):
        """Convert {key<->tuple} to {key1<->value2, key2<->value2 ... }."""
        for i, value in enumerate(self[key]):
            self["%s%.2d" % (key, i + 1)] = value
        del self[key]

    def __unicode__(self):
        name = self.__class__.__name__
        return "<%s %s>" % (name, self.raw)

    def __str__(self):
        return str(self.__unicode__())

    def __repr__(self):
        return str(self.__unicode__())


class LoopDataParserRevB(DataParser):
    """Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2."""

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

    def __init__(self, data, dtime):
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
            self["AlarmEx%.2dLowTemp" % i] = int(self["AlarmExTempHum"][0])
            self["AlarmEx%.2dHighTemp" % i] = int(self["AlarmExTempHum"][1])
            self["AlarmEx%.2dLowHum" % i] = int(self["AlarmExTempHum"][2])
            self["AlarmEx%.2dHighHum" % i] = int(self["AlarmExTempHum"][3])
        del self["AlarmExTempHum"]
        # AlarmSoilLeaf 8bits, 4 bytes
        for i in range(1, 5):
            data = self.raw_bytes[81 + i : 82 + i]
            self["AlarmSoilLeaf"] = bytes_to_binary(data)
            self["Alarm%.2dLowLeafWet" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dHighLeafWet" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dLowSoilMois" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dHighSoilMois" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dLowLeafTemp" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dHighLeafTemp" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dLowSoilTemp" % i] = int(self["AlarmSoilLeaf"][0])
            self["Alarm%.2dHighSoilTemp" % i] = int(self["AlarmSoilLeaf"][0])
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
        return "%s-%s-%s" % (year, month, day)

    def unpack_time(self, time):
        """Given a packed time field, unpack and return "HH:MM" string."""
        # format: HHMM, and space padded on the left.ex: "601" is 6:01 AM
        return "%02d:%02d" % divmod(time, 100)  # covert to "06:01"


class HighLowParserRevB(DataParser):
    """Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2."""

    # Loop data format (RevB)
    LOOP_FORMAT = (
        ("DailyLowBarometer", "H"),
        ("DailyHighBarometer", "H"),
        ("MonthlyLowBar", "H"),
        ("MonthlyHighBar", "H"),
        ("YearLowBarometer", "H"),
        ("YearlyHighBarometer", "H"),
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
        ("DayLowTemperature", "15s"),
        ("DayHiTemperature", "15s"),
        ("TimeDayLowTemperature", "30s"),
        ("TimeDayHiTemperature", "30s"),
        ("MonthHiTemperature", "15s"),
        ("MonthLowTemperature", "15s"),
        ("YearHiTemperature", "15s"),
        ("YearLowTemperature", "15s"),
        ("DayLowHumidity", "8s"),
        ("DayHiHumidity", "8s"),
        ("TimeDayLowHumidity", "16s"),
        ("TimeDayHiHumidity", "16s"),
        ("MonthHiHumidity", "8s"),
        ("MonthLowHumidity", "8s"),
        ("YearHiHumidity", "8s"),
        ("YearLowHumidity", "8s"),
        ("DayHiSoilMoisture", "4s"),
        ("TimeDayHiSoilMoisture", "8s"),
        ("DayLowSoilMoisture", "4s"),
        ("TimeDayLowSoilMoisture", "8s"),
        ("MonthLowSoilMoisture", "4s"),
        ("MonthHiSoilMoisture", "4s"),
        ("YearLowSoilMoisture", "4s"),
        ("YearHiSoilMoisture", "4s"),
        ("DayHiLeafWetness", "4s"),
        ("TimeDayHiLeafWetness", "8s"),
        ("DayLowLeafWetness", "4s"),
        ("TimeDayLowLeafWetness", "8s"),
        ("MonthLowLeafWetness", "4s"),
        ("MonthHiLeafWetness", "4s"),
        ("YearLowLeafWetness", "4s"),
        ("YearHiLeafWetness", "4s"),
    )

    def __init__(self, data):
        super().__init__(data, self.LOOP_FORMAT)
        self["DailyLowBarometer"] = self["DailyLowBarometer"] / 1000
        self["DailyHighBarometer"] = self["DailyHighBarometer"] / 1000
        self["MonthlyLowBar"] = self["MonthlyLowBar"] / 1000
        self["MonthlyHighBar"] = self["MonthlyHighBar"] / 1000
        self["YearLowBarometer"] = self["YearLowBarometer"] / 1000
        self["YearlyHighBarometer"] = self["YearlyHighBarometer"] / 1000
        self["TimeOfDayLowBar"] = self["TimeOfDayLowBar"] / 1000
        self["DailyLowBarometer"] = self["DailyLowBarometer"] / 1000
        self["TTimeOfDayHighBarempIn"] = self["TimeOfDayHighBar"] / 1000
        self["DayHiInsideTemp"] = self["DayHiInsideTemp"] / 10
        self["DayLowInsideTemp"] = self["DayLowInsideTemp"] / 10
        self["MonthLowInTemp"] = self["MonthLowInTemp"] / 10
        self["MonthHiInTemp"] = self["MonthHiInTemp"] / 10
        self["YearLowInTemp"] = self["YearLowInTemp"] / 10
        self["YearHiInTemp"] = self["YearHiInTemp"] / 10
        self["DayLowOutTemp"] = self["DayLowOutTemp"] / 10
        self["DayHiOutTemp"] = self["DayHiOutTemp"] / 10
        self["MonthHiOutTemp"] = self["MonthHiOutTemp"] / 10
        self["MonthLowOutTemp"] = self["MonthLowOutTemp"] / 10
        self["YearHiOutTemp"] = self["YearHiOutTemp"] / 10
        self["YearLowOutTemp"] = self["YearLowOutTemp"] / 10
        self["DayHighRainRate"] = self["DayHighRainRate"] / 100
        self["HourHighRainRate"] = self["HourHighRainRate"] / 100
        self["MonthHighRainRate"] = self["MonthHighRainRate"] / 100
        self["YearHighRainRate"] = self["YearHighRainRate"] / 100
        self["DayLowTemperature"] = self["DayLowTemperature"] / 10
        self["DayHiTemperature"] = self["DayHiTemperature"] / 10
        self["MonthHiTemperature"] = self["MonthHiTemperature"] / 10
        self["MonthLowTemperature"] = self["MonthLowTemperature"] / 10
        self["YearHiTemperature"] = self["YearHiTemperature"] / 10
        self["YearLowTemperature"] = self["YearLowTemperature"] / 10


class ArchiveDataParserRevB(DataParser):
    """Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2."""

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

    def __init__(self, data):
        super(ArchiveDataParserRevB, self).__init__(data, self.ARCHIVE_FORMAT)
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
        """
        self['WindHiDir'] = int(self['WindHiDir'] * 22.5)
        self['WindAvgDir'] = int(self['WindAvgDir'] * 22.5)
        """
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
    DMP_FORMAT = (
        ("Pages", "H"),
        ("Offset", "H"),
        ("CRC", "H"),
    )

    def __init__(self, data):
        super(DmpHeaderParser, self).__init__(data, self.DMP_FORMAT)


class DmpPageParser(DataParser):
    DMP_FORMAT = (
        ("Index", "B"),
        ("Records", "260s"),
        ("unused", "4B"),
        ("CRC", "H"),
    )

    def __init__(self, data):
        super(DmpPageParser, self).__init__(data, self.DMP_FORMAT)


def pack_dmp_date_time(d):
    """Pack `datetime` to DateStamp and TimeStamp VantagePro2 with CRC."""
    vpdate = d.day + d.month * 32 + (d.year - 2000) * 512
    vptime = 100 * d.hour + d.minute
    data = struct.pack(b"HH", vpdate, vptime)
    return VantageProCRC(data).data_with_checksum


def unpack_dmp_date_time(date, time):
    """Unpack `date` and `time` to datetime"""
    if date != 0xFFFF and time != 0xFFFF:
        day = date & 0x1F  # 5 bits
        month = (date >> 5) & 0x0F  # 4 bits
        year = ((date >> 9) & 0x7F) + 2000  # 7 bits
        hour, min_ = divmod(time, 100)
        return datetime(year, month, day, hour, min_)


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
