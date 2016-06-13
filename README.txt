LIBMONETRA LUA 0.9.6

ChangeLog
=========

* 0.9.6 Initial Release

Notes
=====

This library attempts to emulate the libmonetra C API with only slight variations.
A metatable based class approach is used. Initialization is handled via conn = libmonetra.new().
The new function takes host, port and connection method parameters. All subsequent use
should be by using conn:function().

