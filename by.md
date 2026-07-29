# WRECK-IT 7.0 — Memory Forensics Challenge Writeup

**Author:** 4Better  
**Category:** Forensics / Reverse Engineering  
**Flag:** `WRECKIT7{it_wrecked?_again?_lmao}`

---

## Overview

Challenge ini ngasih kita sebuah file memory dump Linux (`memdump.lime`) yang diambil dari sebuah VM yang udah dikompromis. Tujuannya: recover isi file `/secret.txt` yang udah dihapus dan di-exfiltrate sama malware custom yang jalan di dalam VM itu.

Spoiler singkat: ada dua binary custom (`session-handler` dan `gatekeeper`) yang jalan di VM, salah satunya inject shellcode ke memory, buka `/secret.txt`, encode isinya pakai algoritma custom, kirim ke attacker, terus hapus file aslinya. Kita harus reverse algoritma encode-nya dari shellcode yang ke-capture di memory, terus decode data yang masih nyisa di memory buat dapetin flag.

---

## Langkah 1 — Analisis Bash History

Hal pertama yang gue lakuin waktu dapet memory dump Linux adalah cek bash history pake Volatility3. Ini salah satu plugin paling informatif karena langsung nunjukin apa aja yang dikerjain si operator di dalam VM.

```bash
vol3 -f memdump.lime linux.bash
```

Output yang keluar cukup panjang, tapi gue breakdown per PID yang paling relevan.

**PID 5293 (10 Mei, setup awal)**

Ini sesi pertama. Si operator setup SSH server, generate SSH keypair tanpa passphrase, terus cek IP address. Ini tipikal setup akses remote ke VM baru.

**PID 7322 (12 Mei, siang — yang paling penting)**

```
mv secret.txt /secret.txt
chmod -x /usr/libexec/tracker-extract-3 /usr/libexec/tracker-miner-fs-3
sync; echo 3 > /proc/sys/vm/drop_caches
sudo insmod /lib/modules/$(uname -r)/updates/dkms/lime.ko "path=/tmp/memdump.lime format=lime"
```

Ada beberapa hal menarik di sini. Pertama, `secret.txt` dipindah ke root `/` — ini kemungkinan besar lokasi flag. Kedua, GNOME Tracker (file indexing service) dimatiin executable bit-nya, kemungkinan biar aktivitas file gak ke-track. Ketiga, `drop_caches` dijalanin sebelum LiME dump — ini usaha bersih-bersih memory sebelum diambil snapshotnya, tapi ironis karena justru malware-nya sendiri ninggalin jejak di memory. Terakhir, `insmod lime.ko` adalah command yang bikin `memdump.lime` ini sendiri.

**PID 7402 (paralel dengan 7322 — ini yang paling sus)**

```
mkdir -p /usr/bin/wreckit && mv /home/ubuntu/bin/{session-handler,gatekeeper} /usr/bin/wreckit/
chmod +x /usr/bin/wreckit/*
/usr/bin/wreckit/session-handler 31337 &>/dev/null & /usr/bin/wreckit/gatekeeper 31338 &>/dev/null &
```

Dua binary custom (`session-handler` dan `gatekeeper`) dipindah ke `/usr/bin/wreckit/`, dikasih permission execute, terus dijalanin sebagai background process di port 31337 dan 31338. Command ini diulang berkali-kali — ini indikasi proses crash dan restart terus, atau si operator lagi testing.

**Kesimpulan dari bash history:** Ada dua binary custom yang jalan sebagai listener, ada file `/secret.txt` yang dicurigai sebagai flag, dan ada aktivitas mencurigakan lainnya. Next step: analisis memory dari proses-proses itu.

---

## Langkah 2 — Mount Memory Dump dengan MemNixFS

Daripada pake Volatility3 terus buat semua analisis, gue pake **MemNixFS** — tool yang bisa mount memory dump Linux jadi filesystem yang bisa di-browse. Ini bikin analisis jauh lebih gampang karena bisa langsung akses `/proc/<pid>/` virtual dari dump.

```bash
memnixfs -f memdump.lime -mount /home/4Better/mount
```

Setelah di-mount, struktur direktorinya kurang lebih kayak gini:

```
/home/4Better/mount/
  proc/
    11618-session-handler/
      maps
      malfind.txt
      proc.dmp
      environ
      cmdline
      ...
    11619-gatekeeper/
      ...
```

Gue langsung fokus ke `11618-session-handler` karena dari bash history, ini binary yang paling aktif dan mencurigakan.

---

## Langkah 3 — Analisis malfind dan Maps

**Cek malfind:**

```bash
cat /home/4Better/mount/proc/11618-session-handler/malfind.txt
```

Output:

```
# pid 11618 (session-handler): 2 anonymous-executable region(s)

  ★ 0x007f4543d35000  0x007f4543d36000  rwx     4096 B  non-zero [48 c1 c7 0d 48 89 f2 49 ...]
                                                     RWX anonymous mapping — classic code injection
  ★ 0x007ffc0d431000  0x007ffc0d452000  rwx   135168 B  unreadable (paged out)
                                                     RWX anonymous mapping — classic code injection
```

Ada dua region memory yang **RWX** (Read-Write-Execute). Ini red flag klasik di memory forensics karena region normal gak butuh permission tulis sekaligus eksekusi. Kalau ada region yang bisa ditulis sekaligus dieksekusi, itu hampir pasti shellcode injection atau payload yang di-load secara dinamis.

Region pertama (4KB) punya konten yang bisa dibaca: `48 c1 c7 0d 48 89 f2 49...` — ini byte-byte x86-64 yang bisa kita disassemble. Region kedua (132KB) keliatan sebagai "paged out" alias gak ke-capture di dump.

**Cek maps:**

```bash
cat /home/4Better/mount/proc/11618-session-handler/maps
```

Output penting:

```
7f4543d35000-7f4543d36000 rwxp 00000000 00:00 0     ← shellcode (4KB RWX)
7ffc0d431000-7ffc0d452000 rwxp 00000000 00:00 0     ← stack RWX (132KB)
7f4543cfb000-7f4543cfe000 rw-p 00000000 00:00 0     ← anonymous RW (mencurigakan)
00000097b000-00000099c000 rw-p 00000000 00:00 0     ← heap
```

Dari maps, region `7f4543cfb000` itu anonymous RW yang "nyempil" di antara region-region library — ini gak normal. Region library biasanya punya pola berurutan dengan file offset yang naik konsisten, tapi ini anonymous tanpa nama file. Ini kandidat kuat buat tempat data encode-an disimpan.

---

## Langkah 4 — Extract Region Memory dari proc.dmp

`proc.dmp` di MemNixFS bukan raw binary biasa — ini **ELF core file**. Format ini adalah standar Linux buat snapshot proses yang lagi jalan. Semua region memory proses dibungkus di dalamnya dengan metadata lengkap (virtual address, permissions, ukuran).

Cara baca offset tiap region: pakai `readelf`.

```bash
readelf -l /home/4Better/mount/proc/11618-session-handler/proc.dmp
```

Output (potongan yang relevan):

```
LOAD  0x000000000028d000  0x00007f4543d35000  ...  0x1000  RWE   ← shellcode
LOAD  0x0000000000253000  0x00007f4543cfb000  ...  0x3000  RW    ← region cfb
LOAD  0x0000000000007000  0x000000000097b000  ...  0x21000 RW    ← heap
LOAD  0x0000000000292000  0x00007ffc0d431000  ...  0x21000 RWE   ← rwx2
```

Kolom pertama setelah `LOAD` adalah **file offset** — ini yang dipakai buat `dd`. Kolom kedua adalah **virtual address** — ini yang sama dengan yang ada di `maps`. Jadi cara identifikasinya: cocokin virtual address dari `maps` dengan kolom VirtAddr di `readelf`, terus ambil file offset-nya buat `dd`.

Extract tiap region:

```bash
# Shellcode (RWE, 4KB) — offset 0x28d000
dd if=proc.dmp of=shellcode.bin bs=1 skip=$((0x28d000)) count=$((0x1000))

# Region cfb (kandidat encoded data) — offset 0x253000
dd if=proc.dmp of=region_cfb.bin bs=1 skip=$((0x253000)) count=$((0x3000))

# Heap — offset 0x7000
dd if=proc.dmp of=heap.bin bs=1 skip=$((0x7000)) count=$((0x21000))
```

Verifikasi shellcode berhasil di-extract:

```bash
xxd shellcode.bin | head -3
```

```
00000000: 48c1 c70d 4889 f249 89f0 41b1 9e48 b84a  H...H..I..A..H.J
```

Byte `48 c1 c7 0d` cocok sama signature yang ada di malfind. Berhasil.

---

## Langkah 5 — Cek region_cfb (Encoded Data)

```bash
xxd region_cfb.bin | head -5
```

```
00000000: be1f ef19 8054 e144 0f90 c980 e80d 9f93  .....T.D........
00000010: d7cc 9ae8 0fba e358 5437 f70a b153 bc67  .......XT7...S.g
00000020: e530 0000 0000 0000 0000 0000 0000 0000  .0..............
```

35 byte non-zero di awal, setelah itu zeros semua. Ini adalah **encoded `/secret.txt`** yang ditinggal di memory oleh shellcode setelah proses exfiltration. Shellcode-nya rajin bersihin stack dan hapus file aslinya, tapi lupa nge-zero buffer mmap ini sebelum proses berhenti. Ini yang jadi celah forensik kita.

Encoded bytes:
```
be1fef198054e1440f90c980e80d9f93d7cc9ae80fbae3585437f70ab153bc67e530
```

---

## Langkah 6 — Reverse Engineering Shellcode di IDA

Sekarang bagian yang paling seru: kita harus tau algoritma encode-nya biar bisa decode. Caranya: disassemble dan decompile shellcode-nya di IDA Pro.

Load `shellcode.bin` di IDA sebagai **binary file**, architecture **x86-64**.

IDA cuma auto-detect satu fungsi di offset `0x0`. Tapi dari `xxd` kita tau ada dua blok kode sebelum NOP padding (`0x90`) yang dimulai di offset `0x347`. Fungsi kedua ada di offset `0x86` — define manual dengan tekan `G` → ketik `86` → Enter, terus tekan `P` buat create function, lalu `F5` buat decompile.

### Fungsi 1: gen8 (offset 0x0)

Pseudocode dari IDA:

```c
v9 = __ROL8__(v4, 13) ^ 0x5A3C6E1F9B7D2E4A;
// loop 8x
v10 = a4 ^ (v9 >> v8);
v11 = 56 - v8;
v8 += 8;
a4 += 55;
v12 = __ROL1__(v10, 3);
*(buf++) = v12;
v9 ^= (uint64)v12 << v11;
// finalizer
fin = 0x6C62272E07BB0142 * v9;
fin ^= fin >> 17;
for (i = 0; i < 8; i++) buf[i] ^= (fin >> (8*i)) & 0xFF;
```

Fungsi ini nerima sebuah seed (64-bit), terus generate 8 byte output. Ini adalah **key generator** — setiap kali dipanggil dengan seed berbeda, hasilnya berbeda. Algoritmanya mirip splitmix64 yang biasa dipakai sebagai PRNG (Pseudo-Random Number Generator).

### Fungsi 2: main (offset 0x86)

Dari pseudocode dan graph view IDA, urutan operasi di main adalah:

**A. Chain generate keys:**

```c
gen8(load_address);          // hasilnya disimpan di rsp+8  → buf1
seed2 = buf1 as uint64;
gen8(seed2);                 // hasilnya disimpan di rsp+10 → buf2 = key XOR pertama
seed3 = buf2 as uint64;
gen8(seed3);                 // hasilnya disimpan di rsp+18 → buf3 = key XOR kedua
```

Seed pertama adalah **load address shellcode itu sendiri** (`0x7f4543d35000`), yang diambil dengan `lea rdi, [rip]; and rdi, ~0xfff`. Ini teknik yang rapi — key-nya berubah tiap run karena ASLR, tapi selalu bisa direkonstruksi dari memory dump.

**B. Syscall sequence:**

Setelah key di-generate, shellcode jalanin: `open("/secret.txt")` → `mmap` → `read` → `close` → `unlink("/secret.txt")` (hapus file!) → encode → `socket` → `connect(?, :4444)` → `send` → zero stack buffers → `pause()` loop.

**C. Encode loop (dari graph IDA):**

Dari block `loc_1B7` sampai `loc_22F`, encode-nya ada 4 tahap berurutan:

**Tahap 1 — rotate_left:**
```
buf = buf[k:] + buf[:k]   dimana k = min(8, len)
```
Dari graph: ada blok yang nyimpen k byte pertama ke temporary buffer, terus nggeser sisa buffer ke kiri, terus nempel balik temporary ke akhir. Itu persis operasi rotate left.

**Tahap 2 — XOR key2 (loc_1FF):**
```
edx = i % 7    (and edx, 7)
dl  = buf2[i % 8]
buf[i] ^= dl
```

**Tahap 3 — XOR key3 (loc_217):**
```
dl  = buf3[i % 8]
buf[i] ^= dl
```

**Tahap 4 — Permutation (loc_22F):**
```
j = (7*i + 3) % len
swap buf[i] ↔ buf[j]
```
Dari graph: ada `imul rax, rcx, 7` → `add rax, 3` → `idiv rbx` → `rdx` jadi index j → swap.

**Urutan encode lengkap:**
```
1. rotate_left(buf, min(8, len))
2. buf[i] ^= key2[i % 8]
3. buf[i] ^= key3[i % 8]
4. swap buf[i] ↔ buf[(7*i+3) % len]
```

---

## Langkah 7 — Tulis Decoder Python

Sekarang kita punya semua yang dibutuhin. Cara decode: jalanin operasi encode dalam **urutan terbalik** (tahap 4 dulu, terus 3, 2, 1).

Kenapa dibalik? Karena encode itu kayak numpuk lapisan — kalau mau buka, harus kupas dari lapisan paling luar dulu. Kalau lo encode dengan urutan A→B→C, maka decode-nya harus C⁻¹→B⁻¹→A⁻¹.

Operasi yang perlu di-reverse:
- **XOR**: self-invert, `(x ^ k) ^ k = x`, tinggal XOR lagi pakai key yang sama
- **Rotate left k**: di-undo dengan rotate right k, yaitu `buf[-k:] + buf[:-k]`
- **Swap permutation**: self-invert juga, swap yang sama diulang balik ke posisi asal

```python
def rol64(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def rol8(v, n):
    n %= 8
    return ((v << n) | (v >> (8 - n))) & 0xFF

def gen8(seed):
    state = rol64(seed, 13) ^ 0x5A3C6E1F9B7D2E4A
    buf = bytearray(8)
    a4 = 0x9E  # LOBYTE = -98 unsigned
    v8 = 0
    for i in range(8):
        v10 = (a4 ^ (state >> v8)) & 0xFF
        v11 = 56 - v8
        v8 += 8
        a4 = (a4 + 0x37) & 0xFF
        v12 = rol8(v10, 3)
        buf[i] = v12
        state ^= (v12 << v11) & 0xFFFFFFFFFFFFFFFF
    fin = (0x6C62272E07BB0142 * state) & 0xFFFFFFFFFFFFFFFF
    fin ^= (fin >> 17)
    for i in range(8):
        buf[i] ^= (fin >> (8 * i)) & 0xFF
    return buf

# Chain gen8 — reconstruct keys dari load address
load_addr = 0x7f4543d35000
buf1 = gen8(load_addr)
buf2 = gen8(int.from_bytes(buf1, 'little'))   # key XOR pertama
buf3 = gen8(int.from_bytes(buf2, 'little'))   # key XOR kedua

# Encoded data dari region_cfb.bin (offset 0x253000 di proc.dmp)
data = bytearray(bytes.fromhex(
    "be1fef198054e1440f90c980e80d9f93"
    "d7cc9ae80fbae3585437f70ab153bc67e530"
))

# Decode — urutan DIBALIK dari encode

# Undo tahap 4: permutation
for i in reversed(range(len(data))):
    j = (7 * i + 3) % len(data)
    data[i], data[j] = data[j], data[i]

# Undo tahap 3: XOR key3
for i in range(len(data)):
    data[i] ^= buf3[i % 8]

# Undo tahap 2: XOR key2
for i in range(len(data)):
    data[i] ^= buf2[i % 8]

# Undo tahap 1: rotate_right (undo rotate_left)
k = min(8, len(data))
data = data[-k:] + data[:-k]

print(data.decode())
```

Output:

```
WRECKIT7{it_wrecked?_again?_lmao}
```

---

## Kenapa Encoded Data Masih Ada di Memory?

Ini bagian yang menarik dari sisi forensik.

Shellcode-nya sebenarnya cukup niat bersihin jejak: file aslinya di-`unlink`, key material di stack di-zero semua, terus proses masuk ke `pause()` loop (nunggu signal). Tapi ada satu hal yang dia lupa: **buffer hasil `mmap` gak pernah di-`munmap` atau di-zero** sebelum proses berhenti.

Jadi walaupun file `/secret.txt` sudah dihapus dari filesystem dan key sudah dibersihkan dari stack, data hasil encode yang ada di anonymous mmap buffer `0x7f4543cfb000` masih nempel di memory sampai kernel memutuskan reclaim page-nya. Karena LiME dump diambil saat proses masih jalan (di `pause()` loop), page itu masih ada dan ke-capture.

Satu oversight kecil dari si attacker, jadi jalan masuk buat kita.

---

## Tools yang Dipakai

```
Volatility 3      — linux.bash plugin buat bash history
MemNixFS          — mount memory dump jadi virtual filesystem
readelf / dd      — parse ELF core dan extract region memory
IDA Pro 7.6       — disassemble dan decompile shellcode
Python 3          — tulis decoder
```

---

## Flag

```
WRECKIT7{it_wrecked?_again?_lmao}
```
