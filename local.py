# -*- coding: utf-8 -*-

"""
Implements several basic functions:
    printf - Standard (C like) printf function
    sprintf - Standard (C like) sprintf function
"""

import sys
import re
import os

__VER="1.0.0035"

def printf(format, *args):
	"""
Standard (C like) printf function

Parameters:
    format - string
    args - number of arguments to be interpolated with various types

Format:
    %d  Signed integer decimal.
    %i  Signed integer decimal.
    %o  Signed octal value.
    %u  Obsolete type - it is identical to 'd'.
    %x  Signed hexadecimal (lowercase).
    %X  Signed hexadecimal (uppercase).
    %e  Floating point exponential format (lowercase).
    %E  Floating point exponential format (uppercase).
    %f  Floating point decimal format.
    %F  Floating point decimal format.
    %g  Floating point format. Uses lowercase exponential format if exponent is
        less than -4 or not less than precision, decimal format otherwise.
    %G  Floating point format. Uses uppercase exponential format if exponent is
        less than -4 or not less than precision, decimal format otherwise.
    %c  Single byte (accepts integer or single byte objects).
    %b  Bytes (any object that follows the buffer protocol or has __bytes__()).
    %s  's' is an alias for 'b' and should only be used for Python2/3 code bases.
    %a  Bytes (converts any Python object using
        repr(obj).encode('ascii','backslashreplace)).
    %r  'r' is an alias for 'a' and should only be used for Python2/3 code bases.
    %%  No argument is converted, results in a '%' character in the result.

Returns:
    int - number of characters written to stdout

Raises:
    Any Exceptions raised by sys.stdout.write

	"""
	return sys.stdout.write(format % args)

def sprintf(format, *args):
	"""
Standard (C like) sprintf function

Parameters:
    format - string
    args - number of arguments to be interpolated with various types

Format:
    %d  Signed integer decimal.
    %i  Signed integer decimal.
    %o  Signed octal value.
    %u  Obsolete type - it is identical to 'd'.
    %x  Signed hexadecimal (lowercase).
    %X  Signed hexadecimal (uppercase).
    %e  Floating point exponential format (lowercase).
    %E  Floating point exponential format (uppercase).
    %f  Floating point decimal format.
    %F  Floating point decimal format.
    %g  Floating point format. Uses lowercase exponential format if exponent is
        less than -4 or not less than precision, decimal format otherwise.
    %G  Floating point format. Uses uppercase exponential format if exponent is
        less than -4 or not less than precision, decimal format otherwise.
    %c  Single byte (accepts integer or single byte objects).
    %b  Bytes (any object that follows the buffer protocol or has __bytes__()).
    %s  's' is an alias for 'b' and should only be used for Python2/3 code bases.
    %a  Bytes (converts any Python object using
        repr(obj).encode('ascii','backslashreplace)).
    %r  'r' is an alias for 'a' and should only be used for Python2/3 code bases.
    %%  No argument is converted, results in a '%' character in the result.

Returns:
    string - formatted string

Raises:
    TypeError - bad arguments for format string

	"""
	return (format % args)

# Local variables:
# coding: utf-8
# mode: python
# End:
# vim: fileencoding=utf-8 filetype=python :
