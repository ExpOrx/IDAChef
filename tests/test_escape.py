import sys
sys.path.insert(0, ".")

from idachef.core.recipe import Recipe
from idachef.operations.ciphers import XOR
from idachef.operations.arithmetic import SubMod256

# Test \xHH escape parsing in input
input_text = "Lyq\\x60wmLw\\x7Fhsvwtlw}R}shwnr^"
print("Input text:", repr(input_text))

# Manual unescape matching the new _parse_input_bytes logic
result = bytearray()
i = 0
while i < len(input_text):
    if input_text[i:i+2] == "\\x" and i+3 < len(input_text):
        try:
            val = int(input_text[i+2:i+4], 16)
            result.append(val)
            i += 4
            continue
        except ValueError:
            pass
    elif input_text[i:i+2] == "\\n":
        result.append(0x0a)
        i += 2
        continue
    elif input_text[i:i+2] == "\\t":
        result.append(0x09)
        i += 2
        continue
    elif input_text[i:i+2] == "\\r":
        result.append(0x0d)
        i += 2
        continue
    elif input_text[i:i+2] == "\\\\":
        result.append(0x5c)
        i += 2
        continue
    else:
        result.append(ord(input_text[i]))
        i += 1

inp = bytes(result)
print("Parsed bytes hex:", inp.hex())
print("Parsed bytes text:", inp.decode("latin-1"))

# Run recipe: XOR(5) -> SUB(4)
r = Recipe()
x = XOR()
s = SubMod256()
x.args[0]["value"] = "5"
x.args[1]["value"] = "Hex"
s.args[0]["value"] = "4"
s.args[1]["value"] = "Hex"
r.add_step(x)
r.add_step(s)
out = r.bake(inp)

print("XOR5+SUB4 hex:", out.output.hex())
print("XOR5+SUB4 text:", out.output.decode("latin-1"))

# Verify manually for first few bytes
for b in inp[:5]:
    xor5 = b ^ 5
    sub4 = (xor5 - 4) & 0xFF
    print("  %02x -> XOR5=%02x -> SUB4=%02x = %s" % (b, xor5, sub4, chr(sub4) if 32<=sub4<127 else "."))