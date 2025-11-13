"""pyvantagepro2.utils------------------."""

from collections import OrderedDict
import csv
from io import StringIO


async def is_bytes(data) -> bool:
    """Check if data is bytes instance."""

    return isinstance(data, bytes)


async def bytes_to_binary(values: bytes) -> str:
    r"""Convert bytes to binary string representation.

    E.g.
    >>> bytes_to_binary(b"\x4a\xff")
    '0100101011111111'
    """

    if values == 0:
        data = "00000000"
    else:
        data = "".join(format(byte_val, "08b") for byte_val in values)
    return data


async def hex_to_binary(hexstr: str) -> str:
    """Convert hexadecimal string to binary string representation.

    E.g.
    >>> hex_to_binary("FF")
    '11111111'
    """

    return await bytes_to_binary(bytes.fromhex(hexstr))


async def binary_to_int(buf: str, start=0, stop: int | None = None) -> int:
    """Convert binary string representation to integer.

    E.g.
    >>> binary_to_int('1111110')
    126
    >>> binary_to_int('1111110', 0, 2)
    2
    >>> binary_to_int('1111110', 0, 3)
    6
    """

    return int(buf[::-1][start : (stop or len(buf))][::-1], 2)


async def csv_to_dict(file_input, delimiter=","):
    """Deserialize csv to list of dictionaries."""

    delimiter = await to_char(delimiter)
    table = []
    reader = csv.DictReader(file_input, delimiter=delimiter, skipinitialspace=True)
    table = list(reader)
    return ListDict(table)


async def dict_to_csv(items, delimiter, header):
    """Serialize list of dictionaries to csv."""

    content = ""
    if len(items) > 0:
        delimiter = await to_char(delimiter)
        output = StringIO()
        csvwriter = csv.DictWriter(
            output, fieldnames=items[0].keys(), delimiter=delimiter
        )
        if header:
            csvwriter.writerow({key: key for key in items[0]})
            # writeheader is not supported in python2.6
            # csvwriter.writeheader()
        for item in items:
            csvwriter.writerow(dict(item))

        content = output.getvalue()
        output.close()
    return content


async def to_char(string: str) -> str:
    """Convert to character."""
    if len(string) == 0:
        return ""
    return str(string[0])


class Dict(OrderedDict):
    """A dict with somes additional methods."""

    async def filter(self, keys):
        """Create a dict with only the following `keys`.

        >>> mydict = Dict({"name":"foo", "firstname":"bar", "age":1})
        >>> mydict.filter(['age', 'name'])
        {'age': 1, 'name': 'foo'}
        """

        data = Dict()
        real_keys = set(self.keys()) - set(set(self.keys()) - set(keys))
        for key in keys:
            if key in real_keys:
                data[key] = self[key]
        return data

    async def to_csv(self, delimiter=",", header=True):
        """Serialize list of dictionaries to csv."""

        return await dict_to_csv([self], delimiter, header)


class ListDict(list):
    """List of dicts with somes additional methods."""

    async def to_csv(self, delimiter=",", header=True):
        """Serialize list of dictionaries to csv."""

        return await dict_to_csv(list(self), delimiter, header)

    async def filter(self, keys):
        """Create a list of dictionaries with only the following `keys`.

        >>> mylist = ListDict([{"name":"foo", "age":31},
        ...                    {"name":"bar", "age":24}])
        >>> mylist.filter(['name'])
        [{'name': 'foo'}, {'name': 'bar'}]
        """

        items = ListDict()
        for item in self:
            items.append(item.filter(keys))
        return items

    async def sorted_by(self, keyword, reverse=False):
        """Returns list sorted by `keyword`."""
        key_ = keyword
        return ListDict(sorted(self, key=lambda k: k[key_], reverse=reverse))
