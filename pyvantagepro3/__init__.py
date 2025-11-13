'''
    pyvantagepro2
    ------------

    The public API and command-line interface to PyVantagePro2 package.


'''
# Make sure the logger is configured early:
from .logger import LOGGER, active_logger
from .device import VantagePro2

VERSION = '0.0.7dev'
__version__ = VERSION
