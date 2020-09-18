import wallycore as wally


h2b = wally.hex_to_bytes
b2h = wally.hex_from_bytes

h2b_rev = lambda h : wally.hex_to_bytes(h)[::-1]
b2h_rev = lambda b : wally.hex_from_bytes(b[::-1])
