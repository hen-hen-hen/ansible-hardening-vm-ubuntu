#!/usr/bin/env bash
# linux_hardening_audit.sh - read-only Linux security and hardening audit
# Supports Debian/Ubuntu and RHEL/Fedora-family systems.
# Run only on systems you own or are authorized to assess.

set -u

HOST="$(hostname -f 2>/dev/null || hostname)"
DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
REPORT="${1:-linux-hardening-report-${HOST//[^A-Za-z0-9_.-]/_}-$(date +%Y%m%d-%H%M%S).txt}"
WEB_ROOTS="${WEB_ROOTS:-/var/www /var/www/html /srv/www /opt/apps}"
SCORE=100
FINDINGS=0

redact() { sed -E 's/(password|passwd|secret|token|private[_-]?key)[[:space:]]*=[[:space:]]*.*/\1 = [REDACTED]/I'; }
section() { printf '\n=== %s ===\n' "$1"; }
finding() {
  local sev="$1" title="$2" recommendation="$3" deduction
  case "$sev" in CRITICAL) deduction=20;; HIGH) deduction=12;; MEDIUM) deduction=7;; LOW) deduction=3;; INFO) deduction=0;; esac
  SCORE=$((SCORE-deduction)); (( FINDINGS++ ))
  printf '[%s] %s\n  Rekomendasi: %s\n' "$sev" "$title" "$recommendation"
}
cmd_exists() { command -v "$1" >/dev/null 2>&1; }
is_enabled() { systemctl is-enabled "$1" 2>/dev/null | grep -qxE 'enabled|static|alias'; }
is_active() { systemctl is-active "$1" 2>/dev/null | grep -qx active; }
ref() { printf '  Referensi kontrol: %s\n' "$1"; }

# Simpan seluruh output ke report agar tetap portabel di shell minimal.
exec >"$REPORT" 2>&1

printf 'Linux Hardening Audit (read-only)\nHost: %s\nWaktu UTC: %s\n' "$HOST" "$DATE"
printf 'Catatan: hasil ini adalah baseline audit, bukan pengganti pentest atau review konfigurasi aplikasi.\n'

section 'Sistem dan patch'
printf 'OS: '; . /etc/os-release 2>/dev/null && printf '%s %s\n' "${PRETTY_NAME:-unknown}" "${VERSION_ID:-}" || printf 'unknown\n'
printf 'Kernel: '; uname -srmo
if cmd_exists apt-get; then
  updates="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst /{n++} END{print n+0}')"
  printf 'Paket yang dapat di-upgrade: %s\n' "$updates"
  (( updates > 0 )) && finding HIGH 'Terdapat paket yang belum diperbarui' 'Terapkan patch dari repository resmi setelah uji dan jadwalkan pembaruan keamanan rutin.'
elif cmd_exists dnf; then
  updates="$(dnf -q check-update 2>/dev/null | awk 'NF>=3 && $1 !~ /^(Last|Obsoleting|Security)/{n++} END{print n+0}')"
  printf 'Paket yang terdeteksi dari check-update: %s\n' "$updates"
  (( updates > 0 )) && finding HIGH 'Terdapat paket yang belum diperbarui' 'Terapkan patch dari repository resmi setelah uji dan jadwalkan pembaruan keamanan rutin.'
elif cmd_exists yum; then
  yum -q check-update 2>/dev/null | head -20 | redact
  finding INFO 'Manajer paket yum terdeteksi' 'Pastikan security update diotomatisasi dan dipantau.'
else
  finding MEDIUM 'Manajer paket tidak terdeteksi' 'Verifikasi patch management secara manual dan dokumentasikan sumber paket.'
fi

section 'SSH'
sshd_cfg="/etc/ssh/sshd_config"
if [ -r "$sshd_cfg" ]; then
  ssh_value() { awk -v key="$1" 'tolower($1)==tolower(key) && $1 !~ /^#/ {v=$2} END{print v}' "$sshd_cfg"; }
  permit_root="$(ssh_value PermitRootLogin)"; password_auth="$(ssh_value PasswordAuthentication)"; empty_pw="$(ssh_value PermitEmptyPasswords)"; x11="$(ssh_value X11Forwarding)"
  printf 'PermitRootLogin=%s PasswordAuthentication=%s PermitEmptyPasswords=%s X11Forwarding=%s\n' "${permit_root:-default}" "${password_auth:-default}" "${empty_pw:-default}" "${x11:-default}"
  [[ "${permit_root,,}" == yes || "${permit_root,,}" == without-password ]] && finding HIGH 'Login root melalui SSH masih diizinkan' 'Gunakan akun personal + sudo; set PermitRootLogin no dan gunakan MFA/bastion bila tersedia.'
  [[ "${password_auth,,}" == yes ]] && finding MEDIUM 'Autentikasi password SSH aktif' 'Prioritaskan kunci SSH/FIDO2 atau MFA; nonaktifkan password setelah akses alternatif tervalidasi.'
  [[ "${empty_pw,,}" == yes ]] && finding CRITICAL 'SSH mengizinkan password kosong' 'Set PermitEmptyPasswords no dan verifikasi tidak ada akun tanpa password.'
  [[ "${x11,,}" == yes ]] && finding LOW 'X11 forwarding aktif' 'Nonaktifkan X11Forwarding jika tidak diperlukan.'
else
  finding INFO 'Konfigurasi sshd tidak dapat dibaca' 'Jalankan audit sebagai root atau periksa konfigurasi SSH secara manual.'
fi
if cmd_exists ss; then
  printf 'Port listening:\n'; ss -lntup 2>/dev/null | sed -n '1,40p'
  while read -r endpoint; do
    port="${endpoint##*:}"
    case "$endpoint" in *127.0.0.1:*|*\[::1\]:*|*::1:*|*:22|*:80|*:443) continue;; esac
    [ -n "$port" ] && finding MEDIUM "Port listening di luar baseline HTTP/HTTPS/SSH: $endpoint" 'Tutup service yang tidak diperlukan, bind ke loopback/private interface, atau allowlist port tersebut di firewall.'
    ref 'NIST CSF PR.PT-4; MITRE ATT&CK T1049 (System Network Connections Discovery)'
  done < <(ss -lntupH 2>/dev/null | awk '{print $4}')
fi

section 'Akun, privilege, dan file sensitif'
uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | paste -sd ' ' -)"
printf 'Akun UID 0: %s\n' "$uid0"
non_root_uid0="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | paste -sd ' ' -)"
[ -n "$non_root_uid0" ] && finding CRITICAL "Ada akun selain root dengan UID 0: $non_root_uid0" 'Hapus atau ubah UID akun tersebut setelah memastikan dampak dependensi.'
if awk -F: '($2=="" || $2=="!") {print $1}' /etc/shadow 2>/dev/null | grep -q .; then
  finding CRITICAL 'Akun dengan password kosong terdeteksi' 'Kunci akun yang tidak diperlukan dan tetapkan password kuat atau autentikasi kunci.'
else printf 'Password kosong: tidak terdeteksi (atau /etc/shadow tidak dapat dibaca).\n'; fi
if [ -r /etc/sudoers ]; then
  grep -RhsE '^[[:space:]]*[^#].*NOPASSWD|^[[:space:]]*%?ALL[[:space:]]*\(' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -20 | redact
  grep -RhsE '^[[:space:]]*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q . && finding HIGH 'Rule sudo NOPASSWD ditemukan' 'Batasi NOPASSWD hanya untuk command otomatis yang sangat spesifik dan audit seluruh sudoers.'
fi
for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
  [ -e "$f" ] && printf '%-16s %s\n' "$f" "$(stat -c '%A %U:%G' "$f" 2>/dev/null || stat -f '%Sp %Su:%Sg' "$f")"
done
find /home /root -maxdepth 3 -type f \( -name 'authorized_keys' -o -name '*.pem' -o -name 'id_*' \) -perm /077 2>/dev/null | while read -r f; do finding HIGH "Permission terlalu terbuka: $f" 'Batasi private key/authorized_keys dengan chmod 600 atau 700 pada direktori induk.'; done

section 'Firewall dan layanan'
firewall_found=0
if cmd_exists ufw; then firewall_found=1; ufw_status="$(ufw status verbose 2>/dev/null)"; printf '%s\n' "$ufw_status" | head -20; printf '%s\n' "$ufw_status" | grep -q 'Status: active' || finding HIGH 'UFW tidak aktif' 'Aktifkan firewall host dengan kebijakan default deny incoming dan allowlist port yang diperlukan.'; fi
if cmd_exists firewall-cmd; then firewall_found=1; firewall-cmd --state 2>/dev/null; firewall-cmd --list-all 2>/dev/null | head -30; is_active firewalld || finding HIGH 'firewalld tidak aktif' 'Aktifkan firewall host dan batasi port masuk sesuai kebutuhan layanan.'; fi
if cmd_exists nft; then firewall_found=1; nft list ruleset 2>/dev/null | head -30; fi
if [ "$firewall_found" -eq 0 ]; then finding HIGH 'Tidak ada firewall host yang terdeteksi' 'Pasang/aktifkan nftables, firewalld, atau UFW dan uji agar tidak mengunci akses administrasi.'; fi
printf 'Layanan penting:\n'; for svc in auditd rsyslog systemd-journald chronyd ntpd fail2ban; do printf '%-18s active=%s enabled=%s\n' "$svc" "$(is_active "$svc" && echo yes || echo no)" "$(is_enabled "$svc" && echo yes || echo no)"; done
is_active auditd || finding MEDIUM 'auditd tidak aktif' 'Aktifkan audit logging untuk event autentikasi, privilege escalation, dan perubahan konfigurasi.'
is_active fail2ban || finding LOW 'fail2ban tidak aktif' 'Pertimbangkan rate limiting/lockout untuk SSH jika sesuai arsitektur dan kebijakan organisasi.'
ref 'NIST CSF PR.AC-7; MITRE ATT&CK T1110 (Brute Force)'

section 'Service selain SSH dan exposure aplikasi'
if cmd_exists systemctl; then
  printf 'Service aktif (ringkas):\n'
  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -80
  for svc in nginx apache2 httpd php-fpm php8.1-fpm php8.2-fpm php8.3-fpm mysql mariadb postgresql redis redis-server docker containerd named bind9; do
    if is_active "$svc"; then
      printf 'Aktif: %s\n' "$svc"
      case "$svc" in mysql|mariadb|postgresql|redis|redis-server)
        finding MEDIUM "Database/cache service aktif: $svc" 'Pastikan hanya bind ke interface internal/loopback, gunakan autentikasi, TLS, patch rutin, dan firewall allowlist.'
        ref 'OWASP A05 Security Misconfiguration; NIST CSF PR.AC-5'
        ;;
      docker|containerd)
        finding INFO "Container runtime aktif: $svc" 'Audit image provenance, capability, secret, socket exposure, rootless mode, dan network policy.'
        ref 'OWASP A05; MITRE ATT&CK T1611 (Escape to Host)'
        ;;
    esac
    fi
  done
fi

section 'Web root, framework, dan secret'
found_web=0
for root in $WEB_ROOTS; do
  [ -d "$root" ] || continue
  found_web=1
  printf 'Web root: %s (%s)\n' "$root" "$(stat -c '%A %U:%G' "$root" 2>/dev/null || stat -f '%Sp %Su:%Sg' "$root")"
  [ -f "$root/.env" ] && finding CRITICAL "File .env berada di web root: $root/.env" 'Pindahkan secret ke luar document root atau blokir akses web; rotasi secret bila pernah terekspos.' && ref 'OWASP A02 Cryptographic Failures; OWASP A05 Security Misconfiguration'
  [ -f "$root/.git/config" ] && finding HIGH "Direktori .git berada di web root: $root/.git" 'Hapus dari deployment atau blokir akses; repository dapat membocorkan source code dan secret.' && ref 'OWASP A01 Broken Access Control; MITRE ATT&CK T1552.001'
  [ -f "$root/composer.json" ] && printf 'Framework PHP candidate: %s\n' "$root"
  [ -f "$root/artisan" ] && printf 'Laravel candidate: %s\n' "$root"
  [ -f "$root/package.json" ] && printf 'JavaScript/Node candidate: %s\n' "$root"
  [ -f "$root/pom.xml" -o -f "$root/build.gradle" -o -f "$root/build.gradle.kts" ] && printf 'Java build candidate: %s\n' "$root"
  for manifest in composer.lock package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml pom.xml gradle.lockfile; do
    find "$root" -maxdepth 2 -type f -name "$manifest" -print -quit 2>/dev/null | grep -q . || continue
    printf 'Dependency manifest: %s/%s\n' "$root" "$manifest"
  done
  [ -f "$root/storage/logs/laravel.log" ] && find "$root/storage/logs" -type f -perm -0004 -print 2>/dev/null | head -10
  if [ -f "$root/.env" ]; then
    grep -E '^(APP_ENV|APP_DEBUG|APP_URL)=' "$root/.env" 2>/dev/null | redact
    grep -q '^APP_DEBUG=true' "$root/.env" 2>/dev/null && finding HIGH "Laravel APP_DEBUG aktif: $root" 'Set APP_DEBUG=false pada production dan jangan tampilkan stack trace kepada pengguna.' && ref 'OWASP A05 Security Misconfiguration; NIST CSF PR.DS-5'
  fi
  find "$root" -xdev -type f \( -name '*.pem' -o -name '*.key' -o -name '.env*' -o -name 'id_rsa*' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -print 2>/dev/null | head -20 | while read -r secret_file; do
    finding HIGH "Kandidat secret di folder aplikasi: $secret_file" 'Pindahkan secret ke secret manager/environment yang aman dan pastikan file tidak dapat diakses web atau user lain.'
    ref 'OWASP A02; MITRE ATT&CK T1552.001'
  done
done
[ "$found_web" -eq 0 ] && finding INFO 'Web root default tidak ditemukan' 'Set WEB_ROOTS ke lokasi deployment aplikasi untuk mengaudit permission dan file sensitif.'

section 'Permission dan akses user pada aplikasi'
for root in $WEB_ROOTS; do
  [ -d "$root" ] || continue
  printf 'File world-writable (maks. 50): %s\n' "$root"
  find "$root" -xdev -type f -perm -0002 -not -path '*/vendor/*' -not -path '*/node_modules/*' -print 2>/dev/null | head -50
  if find "$root" -xdev -type f -perm -0002 -not -path '*/vendor/*' -not -path '*/node_modules/*' -print -quit 2>/dev/null | grep -q .; then
    finding HIGH "File aplikasi world-writable: $root" 'Gunakan owner/group service yang tepat, permission least privilege, dan pastikan deployment directory tidak writable oleh user umum.'
    ref 'OWASP A01 Broken Access Control; NIST CSF PR.AC-4'
  fi
  find "$root" -xdev -type d -perm -0002 -not -path '*/vendor/*' -not -path '*/node_modules/*' -print 2>/dev/null | head -30
done

section 'DNS, bot, dan anti-DDoS (indikator lokal)'
if cmd_exists ss; then
  ss -lntupH 2>/dev/null | awk '$4 ~ /:53$/ {print "DNS listener: " $4 " " $7}'
  ss -lunpH 2>/dev/null | awk '$4 ~ /:53$/ {print "DNS UDP listener: " $4 " " $6}'
fi
if is_active named || is_active bind9 || is_active unbound || is_active dnsmasq; then
  finding INFO 'DNS service aktif' 'Pastikan recursion tidak terbuka ke Internet, gunakan ACL, rate limiting/RRL, logging, DNSSEC sesuai kebutuhan, dan patch rutin.'
  ref 'NIST CSF PR.PT-4; OWASP A05 Security Misconfiguration'
fi
for cfg in /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
  [ -r "$cfg" ] || continue
  printf 'Web config terdeteksi: %s\n' "$cfg"
  grep -Eis 'limit_req|limit_conn|mod_evasive|mod_security|waf|rate.?limit|proxy_cache' "$cfg" 2>/dev/null | head -20 | redact
done
if ! (grep -RilE 'limit_req|limit_conn|mod_security|mod_evasive|rate.?limit|waf' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | head -1 | grep -q .); then
  finding LOW 'Indikator rate limiting/WAF lokal tidak ditemukan' 'Validasi proteksi bot, scraping, credential stuffing, dan DDoS di reverse proxy/CDN/WAF; cek konfigurasi provider karena kontrol eksternal tidak terlihat dari host.'
  ref 'OWASP API4 Unrestricted Resource Consumption; NIST CSF PR.DS-2'
fi
if [ -r /var/www/html/robots.txt ]; then
  printf 'robots.txt ditemukan; catatan: robots.txt bukan kontrol keamanan.\n'
else
  finding INFO 'robots.txt tidak ditemukan pada web root default' 'Buat robots.txt hanya untuk pengaturan crawler; tetap gunakan autentikasi, authorization, rate limiting, dan WAF sebagai kontrol keamanan.'
fi

section 'Kernel, filesystem, dan permission'
for p in net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.rp_filter; do printf '%-46s %s\n' "$p" "$(sysctl -n "$p" 2>/dev/null || echo unavailable)"; done
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" = 1 ] && finding MEDIUM 'IP forwarding aktif' 'Nonaktifkan jika host bukan router/container host; jika diperlukan, dokumentasikan dan batasi forwarding dengan firewall.'
printf 'Mount penting:\n'; findmnt -rn -o TARGET,FSTYPE,OPTIONS / /tmp /var/tmp /home 2>/dev/null | head -20
for m in /tmp /var/tmp; do
  opts="$(findmnt -rn -o OPTIONS "$m" 2>/dev/null)"
  [ -n "$opts" ] && printf '%s: %s\n' "$m" "$opts"
  [[ -n "$opts" && "$opts" != *nodev* ]] && finding LOW "$m tidak memakai nodev" "Tambahkan nodev pada mount $m jika kompatibel dengan aplikasi."
  [[ -n "$opts" && "$opts" != *nosuid* ]] && finding LOW "$m tidak memakai nosuid" "Tambahkan nosuid pada mount $m jika kompatibel dengan aplikasi."
done
if [ -d /tmp ]; then
  ww="$(find /tmp -xdev -type f -perm -0002 2>/dev/null | head -10)"; [ -n "$ww" ] && finding MEDIUM 'File world-writable ditemukan di /tmp' 'Hapus file sementara yang tidak diperlukan dan periksa proses pemiliknya; gunakan sticky bit dan kontrol service.'
fi

section 'Ringkasan'
[ "$SCORE" -lt 0 ] && SCORE=0
printf 'Skor baseline: %s/100\nTemuan: %s\nReport tersimpan: %s\n' "$SCORE" "$FINDINGS" "$REPORT"
printf 'Prioritas: CRITICAL/HIGH terlebih dahulu, lalu MEDIUM/LOW setelah validasi dampak operasional.\n'

