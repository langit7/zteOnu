# zteOnu

A tool to open the factory / telnet mode on ZTE ONU devices via the `webFac`
interface. Type `./zteonu -h` for help.

## Build

```bash
go build -o zteonu .
```

## Usage

```bash
# Open temp telnet; the client MAC is auto-detected from the route to the ONU
./zteonu -i 192.168.1.1

# Pin the MAC to a specific network interface instead
./zteonu -i 192.168.1.1 --iface en0

# Use the exact client MAC observed by the ONU/ONT (overrides auto-detection)
./zteonu -i 192.168.1.1 --mac <mac-seen-by-ont>

# Use the newer time-qualified version61 method with route-based MAC detection
./zteonu -i 192.168.1.1 --new

# Enable permanent telnet (user: root, pass: Zte521) by restarting telnetd in place, without rebooting
./zteonu -i 192.168.1.1 --telnet

# Same, but apply the settings by rebooting the device instead
./zteonu -i 192.168.1.1 --telnet-restart

# Close temporary factory Telnet
./zteonu -i 192.168.1.1 telnet close

# Enable or disable the serial interface
./zteonu -i 192.168.1.1 serial open
./zteonu -i 192.168.1.1 serial close

# Decrypt /etc/hardcodefile containers
./zteonu hardcode /path/to/hardcode /path/to/hardcodefile/*
```

When neither `--iface` nor `--mac` is given, the client MAC is auto-detected: the tool dials a UDP socket to the ONU
(route lookup only, no packet is sent), reads the chosen source address and fills in the MAC of the interface that owns
it. Every run opens the temporary factory telnet through the `webFac` flow and then **verifies it with an actual telnet
login using the temp credentials**. The flow completing over HTTP is not proof the device accepts them - a mismatched
client MAC still yields credentials, but the telnet they authorize does not work. `--telnet` only decides whether, after
the verification succeeds, the permanent telnet settings are written and applied by **restarting the
`telnetd` service in place, without rebooting**; without it the tool just prints the verified temp credentials and
exits. The in-place restart goes through the device's program manager (`sendcmd -pc kill <pid>`, which the `pc`
supervisor answers by respawning telnetd) and is verified with a fresh `root`/`Zte521` login. `--telnet-restart`
writes the same permanent settings but applies them by rebooting the device; the two flags are mutually exclusive.
The default flow is unchanged. Use `--new` for firmware that requires the time-qualified `version61` authentication and
factory-mode requests; it still uses the MAC-derived `SendInfo` payload, so provide `--mac` or a suitable interface MAC.

## Flags

| Flag               | Short | Default        | Description                                                                                                                                                                 |
|--------------------|-------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--user`           | `-u`  | built-in list  | factory mode auth usernames (comma-separated)                                                                                                                               |
| `--pass`           | `-p`  | built-in list  | factory mode auth passwords (comma-separated)                                                                                                                               |
| `--ip`             | `-i`  | `192.168.1.1`  | ONU ip address                                                                                                                                                              |
| `--port`           |       | `80`            | ONU http port                                                                                                                                                               |
| `--telnet`         |       | `false`        | permanent telnet (user: `root`, pass: `Zte521`) applied by restarting the `telnetd` service in place, without rebooting; only applied after a temp telnet login is verified |
| `--telnet-restart` |       | `false`        | permanent telnet (user: `root`, pass: `Zte521`) applied by rebooting the device; mutually exclusive with `--telnet`                                                         |
| `--tp`             |       | `23`           | ONU telnet port                                                                                                                                                             |
| `--new`            |       | `false`        | use the newer time-qualified `version61` factory method; the payload must contain the client MAC observed by the ONU/ONT                                                     |
| `--iface`          |       | `""`           | network interface whose MAC to use (default: auto-detected from the route to the ONU)                                                                                       |
| `--mac`            | `-m`  | `""`           | exact client MAC observed by the ONU/ONT for the `SendInfo` payload; overrides `--iface` and auto-detection                                                                |

## Notes on the client MAC

The `SendInfo` payload is not tied to a hardcoded MAC. The firmware reads the remote client's MAC at runtime and
compares it with the MAC encoded in the payload. Any six-byte MAC can be encoded, but it must match the client MAC
actually observed by the ONU/ONT:

- With a direct Ethernet connection, the default route-based detection normally selects the correct interface and MAC.
- Use `--iface` to select the interface explicitly, or `--mac` when you know the exact MAC seen by the ONU/ONT.
- Bridges, repeaters, virtual machines, Wi-Fi links and routed setups can cause the ONU/ONT to see a different MAC from
  the one on the selected local interface.
- `--mac` changes only the encoded `SendInfo` payload; it does not change the interface's real source MAC. If they do not
  match, configure or spoof the interface MAC as well.

The previously documented `00:07:29:55:35:57` value was only a captured reference used to validate the algorithm. It
is not hardcoded by the payload generator and is not required by this firmware.

The payload transformation is derived from reverse-engineering the device's verification VM: the 46-byte payload is 12
little-endian `uint16` values (`info=12`), each packed as 2 data bytes + 2 zero bytes (the last value has no trailing
zeros). For each value `w` the device computes `w^1271 mod 2537` and keeps the low byte; the 12 resulting bytes are
grouped by 6 and compared against the client MAC. The first six values are therefore chosen as preimages of the MAC
bytes, i.e. `v` such that `(v^1271 mod 2537) & 0xff`
equals the MAC byte; the remaining six are filler.
