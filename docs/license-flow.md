# Alur Lisensi & Verifikasi Target

Dokumen ini mencatat bukti bahwa gate lisensi tunggal berada di `lambda$showLogin$0`, bukan di tempat lain.

---

## 1. Validasi format

```smali
.method validKey(Ljava/lang/String;)Z
    .locals 1
    const-string v0, "[A-Za-z0-9_\\-]{3,128}"
    invoke-virtual {p1, v0}, Ljava/lang/String;->matches(Ljava/lang/String;)Z
    move-result p1
    return p1
.end method
```

Tidak ada hash, HMAC, signature, atau derivasi kunci. Fungsi ini murni filter karakter.

Dipanggil di dua tempat:

1. `lambda$showLogin$2` — sebelum request dikirim.
2. `startBinary` — sebelum `run.sh` dibuat.

---

## 2. Request verifikasi

`lambda$showLogin$1` membangun body:

```json
{"key":"<input>"}
```

lalu:

```java
httpPostJson("https://sza-license.szax.workers.dev/precheck", body, 10000);
JSONObject o = new JSONObject(resp);
boolean ok = o.optBoolean("ok", false);
String  msg = o.optString("message", ok ? "Key valid" : "Key tidak valid");
```

`ok` diteruskan ke `lambda$showLogin$0` sebagai parameter `p2`.

---

## 3. Gate keputusan

```smali
.method synthetic lambda$showLogin$0$...(Btn p1, Z p2, String p3, String p4, Z p5)V
    const/4 v0, 0x1
    invoke-virtual {p1, v0}, Btn->setEnabled(Z)V
    const-string v1, "LOGIN"
    invoke-virtual {p1, v1}, Btn->setText(...)V

    if-nez p2, :cond_0          ; p2 == ok
    invoke-virtual {p0, p3}, MainActivity->toast(String)V
    return-void
    :cond_0

    iput-object p4, p0, MainActivity->sessionKey:Ljava/lang/String;
    ; simpan key jika checkbox dicentang
    invoke-virtual {p0}, MainActivity->showMain()V
    return-void
.end method
```

Alamat asli:

```text
0x0000bd1a  39040600  if-nez v4, 0x0000bd26
```

---

## 4. Pemakaian session key

Hanya di `startBinary`:

```smali
iget-object v0, p0, MainActivity->sessionKey:Ljava/lang/String;
invoke-virtual {v0}, String->trim()Ljava/lang/String;
invoke-virtual {p0, v7}, MainActivity->validKey(...)Z
if-nez v0, :cond_0
const-string v0, "Key kosong/tidak valid, login ulang"
invoke-virtual {p0}, MainActivity->showLogin()V
return-void
```

Setelah itu key masuk ke script:

```sh
export SZAX_APK=1 SZAX_KEY='<key>' SZAX_VER=<int> SZAX_MODE=<1|2> \
       SZAX_DRIVER=<int> SZAX_HIDE_REC=<0|1>
```

Tidak ada lagi pemeriksaan di sisi Java.

---

## 5. Mengapa bukan field `isPremium`

Seluruh field `MainActivity` yang berhubungan dengan status:

```text
kernelMode   : boolean  -> pilihan metode (ROOT/KERNEL), bukan lisensi
rootOk       : boolean  -> hasil deteksi su
running      : boolean  -> status proses binary
navBusy      : boolean  -> animasi navigasi
```

SharedPreferences yang dipakai:

```text
key, save_key, kernel, ver, drv, hide, run_cfg, bin_ver
```

Tidak ada `premium`, `tier`, `plan`, `expiry`, `trial`, atau `license_valid`.

---

## 6. Uji server

```bash
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"key":"ABC"}' https://sza-license.szax.workers.dev/precheck
# {"ok":false,"message":"Key tidak valid"}

curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"key":"ZZZZ-1234-ABCD-9999"}' https://sza-license.szax.workers.dev/precheck
# {"ok":false,"message":"Key tidak valid"}
```

Format key yang diterima server tidak diketahui; aplikasi hanya membatasi charset dan panjang.

---

## 7. Verifikasi patch

Sebelum build:

```bash
diff -u orig/MainActivity.smali patched/MainActivity.smali
```

Sesudah build:

```bash
r2 -q -c 'aa; afl~lambda_showLogin_0' classes.dex
r2 -q -c 'aa; s <alamat>; pd 8' classes.dex
```

Harus terlihat `const/4 v4, 0x1` tepat sebelum `if-nez v4`.
