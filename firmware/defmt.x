# defmt RTT logging configuration.
#
# Mirrors the defmt-over-RTT setup used by OpenSK / trussed reference binaries
# so existing CI tooling (defmt-print / probe-rs RTT) can decode logs unchanged.

# Default log level for the `defmt` crate (lower numeric = more verbose).
# 32 = WARN+INFO+ERROR; bump to ~64 (TRACE) for verbose bring-up in CI.
severity = "info"

# Pin the timestamp format so CI log regexes stay stable.
timestamp = "seconds"

# Encode defmt interned strings in a stable byte order across hosts.
endianness = "little"
