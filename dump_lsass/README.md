unxor with python:
```python
b = bytearray(open('lsass-xor.dmp', 'rb').read())
for i in range(len(b)):
    b[i] ^= 0x01
open('lssas.dmp', 'wb').write(b)
```
