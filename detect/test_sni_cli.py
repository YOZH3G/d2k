"""Offline regression: decode the actual ClientHello emitted by the CLI."""
import subprocess


def emitted_sni(hex_record):
    data = bytes.fromhex(hex_record)
    pos = 43
    pos += 1 + data[pos]  # session ID
    pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # cipher suites
    pos += 1 + data[pos]  # compression methods
    end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    while pos < end:
        kind = int.from_bytes(data[pos:pos + 2], "big")
        size = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        if kind == 0:
            length = int.from_bytes(data[pos + 3:pos + 5], "big")
            return data[pos + 5:pos + 5 + length].decode("ascii")
        pos += size
    raise AssertionError("SNI extension missing")


names = ["a" * 50 + "." + "b" * 50 + "." + "c" * 50 + ".example.test",
         ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])]
for hello in ["modern", "legacy"]:
    for name in names:
        for explicit in [True, False]:
            args = ["./d2k-detect", "classify", "127.0.0.1:443" if explicit else name + ":443",
                    "--hello", hello, "--dump-trigger"]
            if explicit:
                args += ["--sni", name]
            result = subprocess.run(args, capture_output=True, text=True, check=True)
            assert emitted_sni(result.stdout) == name, "CLI silently changed the requested hostname"
for explicit in [True, False]:
    name = "a" * 256
    args = ["./d2k-detect", "classify", "127.0.0.1:443" if explicit else name + ":443", "--dump-trigger"]
    if explicit:
        args += ["--sni", name]
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode != 0 and not result.stdout, "oversized SNI must fail explicitly"
print("CLI SNI: long explicit/default names preserved; oversized input rejected PASS")
