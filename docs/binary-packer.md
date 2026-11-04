# Binary `szax.arm64` — Catatan Packer

Binary ini bukan bagian dari APK. Launcher mengunduhnya tanpa autentikasi, memverifikasi header `x-sha256`, lalu menjalankannya sebagai root dengan environment `SZAX_KEY`.

## Identitas

```text
size     : 11.021.620 byte
sha256   : 32f468fc32b5513d1ba7e98adeb5a9950ec8f79006ca646cecf76680f3b2b934
format   : ELF64 LSB, AArch64 (0xb7), ET_DYN, statically linked (tanpa interp)
entry    : vaddr 0x01671a6c / paddr 0x00a81a6c
phnum    : 4
```

Program header:

```text
0 PT_LOAD  R+X  off 0x0  vaddr 0x0       filesz 0x1000    memsz 0xbe3651
1 PT_LOAD  R+X  off 0x0  vaddr 0xbf0000  filesz 0xa82867  memsz 0xa82867
2 PT_GNU_STACK
3 PT_NOTE
```

Peta vaddr efektif: `vaddr = 0xbf0000 + p_offset` (cocok dengan entry).

## Indikasi packer

- `strings` menemukan `$Info: This file is packed with the UPX executable packer`.
- Magic `UPX!` di `0x1e0` dan di trailer `0xa82d05`.
- UPX 4.2.4 menolak: `NotPackedException: not packed by UPX`, termasuk dengan `-f`.
- Trailer kustom di akhir file:

```text
0xa82d04  00
0xa82d05  "UPX!"
0xa82d0c  00 * 4
0xa82d10  "SZAX"
0xa82d14  0e 2a 02 01
0xa82d18  16 byte high-entropy
0xa82d24  60 c6 bc 00   -> 12.387.936 (ukuran sebelum packing)
0xa82d28  10 2d a8 00   -> 11.021.616
0xa82d2c  60 c6 bc 00
0xa82d30  52 00 00 af
0xa82d34  e8 01 00 00
```

Entropi per 1 MB menunjukkan campuran area plaintext (~6.2) dan compressed/encrypted (~7.9), sehingga sebagian string masih terbaca (`SZAX_HIDE_SECURE`, `SZAX_DRIVER`, `/proc/%s`, dsb.).

## Stub entry

Disassembly di `0xa81a6c` menunjukkan stub yang:

1. `memfd_create("upx")` (syscall 279),
2. `write()` 4036 byte hasil rekonstruksi stub ke memfd,
3. `mmap()` memfd sebagai RX, `close()`,
4. melompat ke `mmap_base + 0x1c`,
5. `readlinkat`/`openat("/proc/self/exe")`,
6. `mmap` fixed `0x3f410000`, panjang `0xbe3651`,
7. `exit(127)` ketika konteks tidak cocok.

Langkah 6–7 konsisten dengan pemeriksaan integritas/lingkungan: stub membaca executable-nya sendiri, lalu berhenti bila kondisi tidak terpenuhi.

## Emulasi

`tools/emu3.py` dan `tools/emu4.py` adalah emulator Unicorn ARM64 yang mengimplementasikan syscall minimum:

```text
279 memfd_create
56  openat  (/proc/self/exe -> isi file asli)
78  readlinkat
57  close
62  lseek
63  read
64  write
222 mmap
226 mprotect
215 munmap
214 brk
221/281 execve/execveat
93  exit
```

Jalankan:

```bash
python3 tools/emu3.py
```

Log yang diharapkan:

```text
memfd('upx')->11
write(fd=11, len=4036, head=0000ffffffffffffc01ba840...)
mmap(fd=11,len=0xfc4,off=0,flags=0x1) -> 0x38000000
close
readlinkat('/proc/self/exe')->28
openat('/proc/self/exe')->12
mmap(addr=0x3f410000,len=0xbe3651,prot=3,flags=0x32,fd=-1) -> 0x3f410000
exit(127)
```

`exit(127)` terjadi sebelum payload didekompresi, sehingga dump payload belum diperoleh.

## Langkah lanjutan

1. Trace fungsi di blob `0x38000330` yang memutuskan `exit(127)`; kemungkinan pemeriksaan ukuran/hash/auxv.
2. Lengkapi emulasi `auxv` (AT_PHDR, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_ENTRY, AT_RANDOM) agar stub berjalan seperti di Android.
3. Jika payload berhasil didekompresi, cari pembacaan `SZAX_KEY` / request validasi di dalamnya.
