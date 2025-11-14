'''
    pyvantagepro2.parser
    -------------------

    Allows parsing Vantage Pro2 data.


'''
from __future__ import division, unicode_literals
import struct
from datetime import datetime
from array import array
import logging
from .compat import bytes
from .logger import LOGGER
from .utils import (cached_property, bytes_to_hex, Dict, bytes_to_binary,
                    binary_to_int)

_LOGGER = logging.getLogger(__name__)

class VantageProCRC(object):
    '''Implements CRC algorithm, necessary for encoding and verifying data from
    the Davis Vantage Pro unit.'''
    CRC_TABLE = (
        0x0,    0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108,
        0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x210,
        0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b,
        0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de, 0x2462, 0x3443, 0x420,  0x1401,
        0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee,
        0xf5cf, 0xc5ac, 0xd58d, 0x3653, 0x2672, 0x1611, 0x630,  0x76d7, 0x66f6,
        0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d,
        0xc7bc, 0x48c4, 0x58e5, 0x6886, 0x78a7, 0x840,  0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b, 0x5af5,
        0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0xa50,  0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
        0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a, 0x6ca6, 0x7c87, 0x4ce4,
        0x5cc5, 0x2c22, 0x3c03, 0xc60,  0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
        0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13,
        0x2e32, 0x1e51, 0xe70,  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
        0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e,
        0xe16f, 0x1080, 0xa1,   0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x2b1,
        0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
        0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3, 0x14a0,
        0x481,  0x7466, 0x6447, 0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
        0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x691,  0x16b0, 0x6657,
        0x7676, 0x4615, 0x5634, 0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
        0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x8e1,  0x3882,
        0x28a3, 0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0xaf1,  0x1ad0, 0x2ab3, 0x3a92, 0xfd2e,
        0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
        0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0xcc1,  0xef1f, 0xff3e, 0xcf5d,
        0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
        0x2e93, 0x3eb2, 0xed1,  0x1ef0,
    )

    def __init__(self, data):
        self.data = data

    @cached_property
    def checksum(self):
        '''Return CRC calc value from raw serial data.'''
        crc = 0
        if isinstance(self.data, bytes):
            for byte in array(str('B'), bytes(self.data)):
                crc = (self.CRC_TABLE[((crc >> 8) ^ byte)] ^ ((crc & 0xFF) << 8))
            return crc

    @cached_property
    def data_with_checksum(self):
        '''Return packed raw CRC from raw data.'''
        checksum = struct.pack(b'>H', self.checksum)
        return b''.join([self.data, checksum])

    def check(self):
        '''Perform CRC check on raw serial data, return true if valid.
        A valid CRC == 0.'''
        if len(self.data) != 0 and self.checksum == 0:
#            LOGGER.info("Check CRC : OK")
            return True
        else:
#            LOGGER.error("Check CRC : BAD")
            return False


class DataParser(Dict):
    '''Implements a reusable class for working with a binary data structure.
    It provides a named fields interface, similiar to C structures.'''

    def __init__(self, data, data_format, order='='):
        super(DataParser, self).__init__()
        self.fields, format_t = zip(*data_format)
        self.crc_error = False
        if "CRC" in self.fields:
            self.crc_error = not VantageProCRC(data).check()
        format_t = str("%s%s" % (order, ''.join(format_t)))
        self.struct = struct.Struct(format=format_t)
        # save raw_bytes
        self.raw_bytes = data
        # Unpacks data from `raw_bytes` and returns a dication of named fields
        data = self.struct.unpack_from(self.raw_bytes, 0)
        self['Datetime'] = None
        self.update(Dict(zip(self.fields, data)))

    @cached_property
    def raw(self):
        return bytes_to_hex(self.raw_bytes)

    def tuple_to_dict(self, key):
        '''Convert {key<->tuple} to {key1<->value2, key2<->value2 ... }.'''
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



class HiLowParser(Dict):
    """Implements a reusable class for working with a binary data structure.
    It provides a named fields interface, similiar to C structures."""

    def __init__(self, data, data_format, order="="):
        super(HiLowParser, self).__init__()
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
    '''Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2.'''
    # Loop data format (RevB)
    LOOP_FORMAT = (
        ('LOO', '3s'), ('BarTrend', 'B'), ('PacketType', 'B'),
        ('NextRec', 'H'), ('Barometer', 'H'), ('TempIn', 'H'),
        ('HumIn', 'B'), ('TempOut', 'H'), ('WindSpeed', 'B'),
        ('WindSpeed10Min', 'B'), ('WindDir', 'H'), ('ExtraTemps', '7s'),
        ('SoilTemps', '4s'), ('LeafTemps', '4s'), ('HumOut', 'B'),
        ('HumExtra', '7s'), ('RainRate', 'H'), ('UV', 'B'),
        ('SolarRad', 'H'), ('RainStorm', 'H'), ('StormStartDate', 'H'),
        ('RainDay', 'H'), ('RainMonth', 'H'), ('RainYear', 'H'),
        ('ETDay', 'H'), ('ETMonth', 'H'), ('ETYear', 'H'),
        ('SoilMoist', '4s'), ('LeafWetness', '4s'), ('AlarmIn', 'B'),
        ('AlarmRain', 'B'), ('AlarmOut', '2s'), ('AlarmExTempHum', '8s'),
        ('AlarmSoilLeaf', '4s'), ('BatteryStatus', 'B'), ('BatteryVolts', 'H'),
        ('ForecastIcon', 'B'), ('ForecastRuleNo', 'B'), ('SunRise', 'H'),
        ('SunSet', 'H'), ('EOL', '2s'), ('CRC', 'H'),
    )

    def __init__(self, data, dtime):
        super(LoopDataParserRevB, self).__init__(data, self.LOOP_FORMAT)
        self['Datetime'] = dtime
        self['Barometer'] = self['Barometer'] / 1000
        self['TempIn'] = self['TempIn'] / 10
        self['TempOut'] = self['TempOut'] / 10
        self['RainRate'] = self['RainRate'] / 100
        self['RainStorm'] = self['RainStorm'] / 100
        # Given a packed storm date field, unpack and return date
        self['StormStartDate'] = self.unpack_storm_date()
        # rain totals
        self['RainDay'] = self['RainDay'] / 100
        self['RainMonth'] = self['RainMonth'] / 100
        self['RainYear'] = self['RainYear'] / 100
        # evapotranspiration totals
        self['ETDay'] = self['ETDay'] / 1000
        self['ETMonth'] = self['ETMonth'] / 100
        self['ETYear'] = self['ETYear'] / 100
        # battery statistics
        self['BatteryVolts'] = self['BatteryVolts'] * 300 / 512 / 100
        # sunrise / sunset
        self['SunRise'] = self.unpack_time(self['SunRise'])
        self['SunSet'] = self.unpack_time(self['SunSet'])
        # convert to int
        self['HumExtra'] = struct.unpack(b'7B', self['HumExtra'])
        self['ExtraTemps'] = struct.unpack(b'7B', self['ExtraTemps'])
        self['SoilMoist'] = struct.unpack(b'4B', self['SoilMoist'])
        self['SoilTemps'] = struct.unpack(b'4B', self['SoilTemps'])
        self['LeafWetness'] = struct.unpack(b'4B', self['LeafWetness'])
        self['LeafTemps'] = struct.unpack(b'4B', self['LeafTemps'])

        # Inside Alarms bits extraction, only 7 bits are used
        self['AlarmIn'] = bytes_to_binary(self.raw_bytes[70:71])
        self['AlarmInFallBarTrend'] = int(self['AlarmIn'][0])
        self['AlarmInRisBarTrend'] = int(self['AlarmIn'][1])
        self['AlarmInLowTemp'] = int(self['AlarmIn'][2])
        self['AlarmInHighTemp'] = int(self['AlarmIn'][3])
        self['AlarmInLowHum'] = int(self['AlarmIn'][4])
        self['AlarmInHighHum'] = int(self['AlarmIn'][5])
        self['AlarmInTime'] = int(self['AlarmIn'][6])
        del self['AlarmIn']
        # Rain Alarms bits extraction, only 5 bits are used
        self['AlarmRain'] = bytes_to_binary(self.raw_bytes[71:72])
        self['AlarmRainHighRate'] = int(self['AlarmRain'][0])
        self['AlarmRain15min'] = int(self['AlarmRain'][1])
        self['AlarmRain24hour'] = int(self['AlarmRain'][2])
        self['AlarmRainStormTotal'] = int(self['AlarmRain'][3])
        self['AlarmRainETDaily'] = int(self['AlarmRain'][4])
        del self['AlarmRain']
        # Oustide Alarms bits extraction, only 13 bits are used
        self['AlarmOut'] = bytes_to_binary(self.raw_bytes[72:73])
        self['AlarmOutLowTemp'] = int(self['AlarmOut'][0])
        self['AlarmOutHighTemp'] = int(self['AlarmOut'][1])
        self['AlarmOutWindSpeed'] = int(self['AlarmOut'][2])
        self['AlarmOut10minAvgSpeed'] = int(self['AlarmOut'][3])
        self['AlarmOutLowDewpoint'] = int(self['AlarmOut'][4])
        self['AlarmOutHighDewPoint'] = int(self['AlarmOut'][5])
        self['AlarmOutHighHeat'] = int(self['AlarmOut'][6])
        self['AlarmOutLowWindChill'] = int(self['AlarmOut'][7])
        self['AlarmOut'] = bytes_to_binary(self.raw_bytes[73])
        self['AlarmOutHighTHSW'] = int(self['AlarmOut'][0])
        self['AlarmOutHighSolarRad'] = int(self['AlarmOut'][1])
        self['AlarmOutHighUV'] = int(self['AlarmOut'][2])
        self['AlarmOutUVDose'] = int(self['AlarmOut'][3])
        self['AlarmOutUVDoseEnabled'] = int(self['AlarmOut'][4])
        del self['AlarmOut']
        # AlarmExTempHum bits extraction, only 3 bits are used, but 7 bytes
        for i in range(1, 8):
            data = self.raw_bytes[73 + i:74 + i]
            self['AlarmExTempHum'] = bytes_to_binary(data)
            self['AlarmEx%.2dLowTemp' % i] = int(self['AlarmExTempHum'][0])
            self['AlarmEx%.2dHighTemp' % i] = int(self['AlarmExTempHum'][1])
            self['AlarmEx%.2dLowHum' % i] = int(self['AlarmExTempHum'][2])
            self['AlarmEx%.2dHighHum' % i] = int(self['AlarmExTempHum'][3])
        del self['AlarmExTempHum']
        # AlarmSoilLeaf 8bits, 4 bytes
        for i in range(1, 5):
            data = self.raw_bytes[81 + i:82 + i]
            self['AlarmSoilLeaf'] = bytes_to_binary(data)
            self['Alarm%.2dLowLeafWet' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dHighLeafWet' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dLowSoilMois' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dHighSoilMois' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dLowLeafTemp' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dHighLeafTemp' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dLowSoilTemp' % i] = int(self['AlarmSoilLeaf'][0])
            self['Alarm%.2dHighSoilTemp' % i] = int(self['AlarmSoilLeaf'][0])
        del self['AlarmSoilLeaf']
        # delete unused values
        del self['LOO']
        del self['NextRec']
        del self['PacketType']
        del self['EOL']
        del self['CRC']
        # Tuple to dict
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("HumExtra")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("SoilMoist")

    def unpack_storm_date(self):
        '''Given a packed storm date field, unpack and return date.'''
        date = bytes_to_binary(self.raw_bytes[48:50])
        date = date[8:16] + date[0:8]
        year = binary_to_int(date, 0, 7) + 2000
        day = binary_to_int(date, 7, 12)
        month = binary_to_int(date, 12, 16)
        return "%s-%s-%s" % (year, month, day)

    def unpack_time(self, time):
        '''Given a packed time field, unpack and return "HH:MM" string.'''
        # format: HHMM, and space padded on the left.ex: "601" is 6:01 AM
        return "%02d:%02d" % divmod(time, 100)  # covert to "06:01"


class HighLowParserRevB(HiLowParser):
    """Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2."""

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
    
    def __init__(self, data):
        super().__init__(data, self.LOOP_FORMAT)
        try:
            self["DailyLowBarometer"] = self["DailyLowBarometer"] / 1000
            self["DailyHighBarometer"] = self["DailyHighBarometer"] / 1000
            self["MonthlyLowBar"] = self["MonthlyLowBar"] / 1000
            self["MonthlyHighBar"] = self["MonthlyHighBar"] / 1000
            self["YearLowBarometer"] = self["YearLowBarometer"] / 1000
            self["YearlyHighBarometer"] = self["YearlyHighBarometer"] / 1000
            self["TimeOfDayLowBar"] = self["TimeOfDayLowBar"] / 100
            self["TimeOfDayHighBar"] = self["TimeOfDayHighBar"] / 100
            self["TimeOfHighWindSpeed"] = self["TimeOfHighWindSpeed"] / 100
            self["DayHiInsideTemp"] = self["DayHiInsideTemp"] / 10
            self["DayLowInsideTemp"] = self["DayLowInsideTemp"] / 10
            self["TimeDayHiInTemp"] = self["TimeDayHiInTemp"] / 100
            self["TimeDayLowInTemp"] = self["TimeDayLowInTemp"] / 100
            self["MonthLowInTemp"] = self["MonthLowInTemp"] / 10
            self["MonthHiInTemp"] = self["MonthHiInTemp"] / 10
            self["YearLowInTemp"] = self["YearLowInTemp"] / 10
            self["YearHiInTemp"] = self["YearHiInTemp"] / 10
            self["TimeDayHiInHum"] = self["TimeDayHiInHum"] / 100
            self["TimeDayLowInHum"] = self["TimeDayLowInHum"] / 100
            self["DayLowOutTemp"] = self["DayLowOutTemp"] / 10
            self["DayHiOutTemp"] = self["DayHiOutTemp"] / 10
            self["TimeDayLowOutTemp"] = self["TimeDayLowOutTemp"] / 100
            self["TimeDayHiOutTemp"] = self["TimeDayHiOutTemp"] / 100
            self["MonthHiOutTemp"] = self["MonthHiOutTemp"] / 10
            self["MonthLowOutTemp"] = self["MonthLowOutTemp"] / 10
            self["YearHiOutTemp"] = self["YearHiOutTemp"] / 10
            self["YearLowOutTemp"] = self["YearLowOutTemp"] / 10
            self["TimeDayLowDewPoint"] = self["TimeDayLowDewPoint"] / 100
            self["TimeDayHiDewPoint"] = self["TimeDayHiDewPoint"] / 100
            self["TimeDayLowChill"] = self["TimeDayLowChill"] / 100
            self["TimeofDayHighHeat"] = self["TimeofDayHighHeat"] / 100
            self["TimeofDayHighTHSW"] = self["TimeofDayHighTHSW"] / 100
            self["TimeofDayHighSolar"] = self["TimeofDayHighSolar"] / 100
            self["TimeofDayHighUV"] = self["TimeofDayHighUV"] / 100
            self["DayHighRainRate"] = self["DayHighRainRate"] / 100
            self["TimeofDayHighRainRate"] = self["TimeofDayHighRainRate"] / 100
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
            self["TimeDayLowTempExtraTemp2"] = self["TimeDayLowTempExtraTemp2"] / 10
            self["TimeDayLowTempExtraTemp3"] = self["TimeDayLowTempExtraTemp3"] / 10
            self["TimeDayLowTempExtraTemp4"] = self["TimeDayLowTempExtraTemp4"] / 10
            self["TimeDayLowTempExtraTemp5"] = self["TimeDayLowTempExtraTemp5"] / 10
            self["TimeDayLowTempExtraTemp6"] = self["TimeDayLowTempExtraTemp6"] / 10
            self["TimeDayLowTempExtraTemp7"] = self["TimeDayLowTempExtraTemp7"] / 10
            self["TimeDayLowTempExtraTemp8"] = self["TimeDayLowTempExtraTemp8"] / 10
            self["TimeDayLowTempSoil1"] = self["TimeDayLowTempSoil1"] / 100
            self["TimeDayLowTempSoil2"] = self["TimeDayLowTempSoil2"] / 100
            self["TimeDayLowTempSoil3"] = self["TimeDayLowTempSoil3"] / 100
            self["TimeDayLowTempSoil4"] = self["TimeDayLowTempSoil4"] / 100
            self["TimeDayLowTempLeaf1"] = self["TimeDayLowTempLeaf1"] / 100
            self["TimeDayLowTempLeaf2"] = self["TimeDayLowTempLeaf2"] / 100
            self["TimeDayLowTempLeaf3"] = self["TimeDayLowTempLeaf3"] / 100
            self["TimeDayLowTempLeaf4"] = self["TimeDayLowTempLeaf4"] / 100
            self["TimeDayHiTempExtraTemp2"] = self["TimeDayHiTempExtraTemp2"] / 100
            self["TimeDayHiTempExtraTemp3"] = self["TimeDayHiTempExtraTemp3"] / 100
            self["TimeDayHiTempExtraTemp4"] = self["TimeDayHiTempExtraTemp4"] / 100
            self["TimeDayHiTempExtraTemp5"] = self["TimeDayHiTempExtraTemp5"] / 100
            self["TimeDayHiTempExtraTemp6"] = self["TimeDayHiTempExtraTemp6"] / 100
            self["TimeDayHiTempExtraTemp7"] = self["TimeDayHiTempExtraTemp7"] / 100
            self["TimeDayHiTempExtraTemp8"] = self["TimeDayHiTempExtraTemp8"] / 100
            self["TimeDayHiTempSoil1"] = self["TimeDayHiTempSoil1"] / 100
            self["TimeDayHiTempSoil2"] = self["TimeDayHiTempSoil2"] / 100
            self["TimeDayHiTempSoil3"] = self["TimeDayHiTempSoil3"] / 100
            self["TimeDayHiTempSoil4"] = self["TimeDayHiTempSoil4"] / 100
            self["TimeDayHiTempLeaf1"] = self["TimeDayHiTempLeaf1"] / 100
            self["TimeDayHiTempLeaf2"] = self["TimeDayHiTempLeaf2"] / 100
            self["TimeDayHiTempLeaf3"] = self["TimeDayHiTempLeaf3"] / 100
            self["TimeDayHiTempLeaf4"] = self["TimeDayHiTempLeaf4"] / 100
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
            self["TimeDayLowOutHum"] = self["TimeDayLowOutHum"] / 10
            self["TimeDayLowOutExtraHum2"] = self["TimeDayLowOutExtraHum2"] / 100
            self["TimeDayLowOutExtraHum3"] = self["TimeDayLowOutExtraHum3"] / 100
            self["TimeDayLowOutExtraHum4"] = self["TimeDayLowOutExtraHum4"] / 100
            self["TimeDayLowOutExtraHum5"] = self["TimeDayLowOutExtraHum5"] / 100
            self["TimeDayLowOutExtraHum6"] = self["TimeDayLowOutExtraHum6"] / 100
            self["TimeDayLowOutExtraHum7"] = self["TimeDayLowOutExtraHum7"] / 100
            self["TimeDayLowOutExtraHum8"] = self["TimeDayLowOutExtraHum8"] / 100
            self["TimeDayHiOutHum"] = self["TimeDayHiOutHum"] / 100
            self["TimeDayHiOutExtraHum2"] = self["TimeDayHiOutExtraHum2"] / 100
            self["TimeDayHiOutExtraHum3"] = self["TimeDayHiOutExtraHum3"] / 100
            self["TimeDayHiOutExtraHum4"] = self["TimeDayHiOutExtraHum4"] / 100
            self["TimeDayHiOutExtraHum5"] = self["TimeDayHiOutExtraHum5"] / 100
            self["TimeDayHiOutExtraHum6"] = self["TimeDayHiOutExtraHum6"] / 100
            self["TimeDayHiOutExtraHum7"] = self["TimeDayHiOutExtraHum7"] / 100
            self["TimeDayHiOutExtraHum8"] = self["TimeDayHiOutExtraHum8"] / 100
        except Exception as e:
            _LOGGER.error(e)
        
class ArchiveDataParserRevB(DataParser):
    '''Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2.'''

    ARCHIVE_FORMAT = (
        ('DateStamp',      'H'), ('TimeStamp',   'H'), ('TempOut',      'H'),
        ('TempOutHi',      'H'), ('TempOutLow',  'H'), ('RainRate',     'H'),
        ('RainRateHi',     'H'), ('Barometer',   'H'), ('SolarRad',     'H'),
        ('WindSamps',      'H'), ('TempIn',      'H'), ('HumIn',        'B'),
        ('HumOut',         'B'), ('WindAvg',     'B'), ('WindHi',       'B'),
        ('WindHiDir',      'B'), ('WindAvgDir',  'B'), ('UV',           'B'),
        ('ETHour',         'B'), ('SolarRadHi',  'H'), ('UVHi',         'B'),
        ('ForecastRuleNo', 'B'), ('LeafTemps',  '2s'), ('LeafWetness', '2s'),
        ('SoilTemps',     '4s'), ('RecType',     'B'), ('ExtraHum',    '2s'),
        ('ExtraTemps',    '3s'), ('SoilMoist',  '4s'),
    )

    def __init__(self, data):
        super(ArchiveDataParserRevB, self).__init__(data, self.ARCHIVE_FORMAT)
        self['raw_datestamp'] = bytes_to_binary(self.raw_bytes[0:4])
        self['Datetime'] = unpack_dmp_date_time(self['DateStamp'],
                                                self['TimeStamp'])
        del self['DateStamp']
        del self['TimeStamp']
        self['TempOut'] = self['TempOut'] / 10
        self['TempOutHi'] = self['TempOutHi'] / 10
        self['TempOutLow'] = self['TempOutLow'] / 10
        self['Barometer'] = self['Barometer'] / 1000
        self['TempIn'] = self['TempIn'] / 10
        self['UV'] = self['UV'] / 10
        self['ETHour'] = self['ETHour'] / 1000
        '''
        self['WindHiDir'] = int(self['WindHiDir'] * 22.5)
        self['WindAvgDir'] = int(self['WindAvgDir'] * 22.5)
        '''
        SoilTempsValues = struct.unpack(b'4B', self['SoilTemps'])
        self['SoilTemps'] = tuple((t - 90) for t in SoilTempsValues)

        self['ExtraHum'] = struct.unpack(b'2B', self['ExtraHum'])
        self['SoilMoist'] = struct.unpack(b'4B', self['SoilMoist'])
        LeafTempsValues = struct.unpack(b'2B', self['LeafTemps'])
        self['LeafTemps'] = tuple((t - 90) for t in LeafTempsValues)
        self['LeafWetness'] = struct.unpack(b'2B', self['LeafWetness'])
        ExtraTempsValues = struct.unpack(b'3B', self['ExtraTemps'])
        self['ExtraTemps'] = tuple((t - 90) for t in ExtraTempsValues)
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("SoilMoist")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("ExtraHum")


class DmpHeaderParser(DataParser):
    DMP_FORMAT = (
        ('Pages',   'H'),  ('Offset',   'H'),  ('CRC',     'H'),
    )

    def __init__(self, data):
        super(DmpHeaderParser, self).__init__(data, self.DMP_FORMAT)


class DmpPageParser(DataParser):
    DMP_FORMAT = (
        ('Index',   'B'),  ('Records',   '260s'),  ('unused',     '4B'),
        ('CRC',   'H'),
    )

    def __init__(self, data):
        super(DmpPageParser, self).__init__(data, self.DMP_FORMAT)


def pack_dmp_date_time(d):
    '''Pack `datetime` to DateStamp and TimeStamp VantagePro2 with CRC.'''
    vpdate = d.day + d.month * 32 + (d.year - 2000) * 512
    vptime = 100 * d.hour + d.minute
    data = struct.pack(b'HH', vpdate, vptime)
    return VantageProCRC(data).data_with_checksum


def unpack_dmp_date_time(date, time):
    '''Unpack `date` and `time` to datetime'''
    if date != 0xffff and time != 0xffff:
        day = date & 0x1f                     # 5 bits
        month = (date >> 5) & 0x0f            # 4 bits
        year = ((date >> 9) & 0x7f) + 2000    # 7 bits
        hour, min_ = divmod(time, 100)
        return datetime(year, month, day, hour, min_)


def pack_datetime(dtime):
    '''Returns packed `dtime` with CRC.'''
    data = struct.pack(b'>BBBBBB', dtime.second, dtime.minute,
                       dtime.hour, dtime.day, dtime.month, dtime.year - 1900)
    return VantageProCRC(data).data_with_checksum


def unpack_datetime(data):
    '''Return unpacked datetime `data` and check CRC.'''
    VantageProCRC(data).check()
    s, m, h, day, month, year = struct.unpack(b'>BBBBBB', data[:6])
    return datetime(year + 1900, month, day, h, m, s)






