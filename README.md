This is a small, simple implementation of the various SHA2 varieties,
including HMAC versions.

Advantages:
* Small (<500 lines, including header).
* Simple to integrate (single .c and .h).
* Public domain.
* Includes HMAC support.
* Simple API, for example removing version complications.
* Code clearly maps to standard.
* Only requires memcpy/memset and uint\*\_t from your build environment.
* No dynamic allocation.

Disadvantages:
* Probably not the very fastest implementation (but not slow, either).

Use cases:
* Simple drop-in for a project written under any license (including commercial).
* Clear code and unencumbered license means can be easily instrumented and used when debugging a new implementation, perhaps in an uncommon language or IP-restricted environment.

100% human authored.

