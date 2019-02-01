# README

This file describes the contents of the other files in this directory. Each of the
files named `file_#` were created using the below bash for loop on a macOS
system:

```bash
for i in 1 2 3; do dd if=/dev/urandom of="file_$i" bs=1K count=200; done
```

These files are treated as "originals" and variations of these files were
generated to demonstrate how ssdeep can compare files through different types
of modifications.

The below descriptions identify what changes were made to each of the
files. For simplicity, we append the letter "a" after each modified version
so it is clear which original they relate to and that they are a modified
version of the original.

All offsets are decimal, not hexadecimal.

## `file_1a`

from decimal offset 27000 of `file_1`, 24000 bytes were selected and moved
to offset 74000 (50000)

## `file_2a`

from decimal offset 50000 of `file_2`, the same 24000 bytes from `file_1` were
inserted

## `file_3a`

from decimal offset 0 of `file_3`, 3500 bytes were removed.

