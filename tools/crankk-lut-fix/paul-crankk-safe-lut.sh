#!/bin/sh
# PAUL_CRANKK_SAFE_LUT_V1
#
# Problem: most Crankk pktfwd templates (rak, panther_x2/sx1302, bobcat/sx1302,
# nebra/sx1302, pisces, cotx, helium_og, tapdo, controllino, browan/sx1302)
# label SX1250 LUT entries "12..27 dBm" with pa_gain 1 / pwr_idx 4..20. In the
# Semtech SX1302 reference table pa_gain 1 / pwr_idx 4 is ~21 dBm, so every
# request is sent ~9 dB louder than labelled, and a request below 12 dBm (all
# PAUL EU868 traffic) falls back to LUT[0] = ~21 dBm conducted.
#
# Fix: Crankk's PacketForwarder.checkConfig() uses /data/global_conf.json when it
# exists, and fixConfig() still patches ID/ports/antenna/multiplexer/SPI/rssi
# afterwards. We copy the RUNNING ./global_conf.json, replace only
# SX130x_conf.radio_0.tx_gain_lut with the PAUL table (= PAUL_SX1302_LOW_POWER_LUT_V1
# of paul-sx1302: 2..11 dBm extrapolated, 12..17 dBm Semtech reference, pa_gain 0)
# and store it as /data/global_conf.json. Survives Crankk restarts/recreates
# (same crankk_data volume). Nothing else is touched.
#
# Usage (root, docker group or sudo):  sh paul-crankk-safe-lut.sh --check|--apply|--uninstall|--status
# One-liner: (curl -fsSL https://node.paulnetwork.io/lut-fix || wget -qO- https://node.paulnetwork.io/lut-fix) > /tmp/paul-lut-fix.sh && sh /tmp/paul-lut-fix.sh --check
# Env: C=<container> (default crankk-pktfwd), WAIT=<s> (default 240)
set -u
MODE=${1:---check}
C=${C:-crankk-pktfwd}
WAIT=${WAIT:-240}
TS=$(date -u +%Y%m%dT%H%M%SZ)
say() { echo "[paul-lut] $*"; }
die() { say "ERROR: $*"; exit "${2:-1}"; }
# Docker access: root / docker group (Bobcat, Buildroot: user crankk = uid 0) -> plain docker;
# otherwise passwordless sudo; otherwise interactive sudo (asks for the password once).
command -v docker >/dev/null 2>&1 || die "docker not found - is this a Crankk gateway?" 2
if docker info >/dev/null 2>&1; then D="docker"
elif command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then D="sudo -n docker"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ] && sudo -v; then D="sudo docker"
else die "no docker access: run as root (e.g. 'su -' first) or as a user with sudo / in the docker group" 2
fi
# hard time limit for docker logs (hangs on a corrupt json log after an unclean shutdown)
if command -v timeout >/dev/null 2>&1 && timeout -s KILL 2 true 2>/dev/null; then TO="timeout -s KILL 25"; else TO=""; fi
if [ "$MODE" = "--apply" ] && [ ! -f "$0" ]; then
  die "download the script to a file first (it restarts itself in the background), see paulnetwork.io lut-fix instructions" 2
fi

$D inspect "$C" >/dev/null 2>&1 || die "container $C not found" 2
[ "$($D inspect -f '{{.State.Running}}' "$C")" = true ] || die "container $C not running" 2
$D inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$C" | grep -qw /data || die "$C has no /data mount (custom conf would not persist)" 2

# --- JS run inside the container (node 18 is in crankkster/pktfwd) -----------------
JS='
const fs=require("fs");const mode=process.argv[1];const ts=process.argv[2];
const STATE="/data/paul-safe-lut.json",CUSTOM="/data/global_conf.json",RUN="./global_conf.json";
const PAUL=[[2,5],[3,6],[4,7],[5,8],[6,9],[7,10],[8,11],[9,12],[10,13],[11,14],[12,15],[13,16],[14,17],[15,19],[16,20],[17,22]]
  .map(([p,i])=>({rf_power:p,pa_gain:0,pwr_idx:i}));
const strip=t=>t.replace(/\/\*[\s\S]*?\*\//g,"");
const read=f=>{try{return fs.readFileSync(f,"utf8")}catch(e){return null}};
const sha=t=>require("crypto").createHash("sha256").update(t).digest("hex");
const out=o=>{console.log(JSON.stringify(o));};
const lutStr=l=>(l||[]).map(e=>e.rf_power+":"+e.pa_gain+"/"+e.pwr_idx).join(" ");
function analyse(txt){
  const j=JSON.parse(strip(txt));const sx=j.SX130x_conf;
  if(!sx) return {j,kind:"sx1301",ok:false,why:"SX1301 config - LUT format differs, not handled"};
  const r0=sx.radio_0||{};
  if(r0.type!=="SX1250") return {j,kind:"other",ok:false,why:"radio_0 type "+r0.type+" - not handled"};
  const lut=r0.tx_gain_lut||[];
  const same=JSON.stringify(lut)===JSON.stringify(PAUL);
  const low=lut.filter(e=>e.rf_power<=17);
  const shifted=low.some(e=>e.pa_gain===1);
  return {j,kind:"sx1250",ok:true,same,shifted,lut,ant:sx.antenna_gain,lut_min:Math.min(...lut.map(e=>e.rf_power))};
}
const run=read(RUN), custom=read(CUSTOM), state=read(STATE);
if(!run){out({error:"no running global_conf.json"});process.exit(3);}
const a=analyse(run);
const st=state?JSON.parse(state):null;
const info={mode,kind:a.kind,handled:a.ok,why:a.why,running_lut:lutStr(a.lut),paul_lut_active:!!a.same,
  crankk_shifted_lut:!!a.shifted,antenna_gain:a.ant,custom_conf:!!custom,custom_is_paul:!!(st&&custom&&sha(custom)===st.sha256),state:st?{ts:st.ts,backup:st.backup}:null};
if(mode==="check"||mode==="status"){out(info);process.exit(0);}
if(mode==="apply"){
  if(!a.ok){out(Object.assign(info,{error:a.why}));process.exit(4);}
  if(a.same&&info.custom_is_paul){out(Object.assign(info,{result:"already"}));process.exit(0);}
  const sx=a.j.SX130x_conf; const old=sx.radio_0.tx_gain_lut; sx.radio_0.tx_gain_lut=PAUL;
  // Crankk start: chip_id often fails -> SX1301 binary first. Without an SX1301_conf it only logs
  // "does not contain SX1301_conf" and never retries. With the Crankk SX1301 block it fails with
  // "failed to start the concentrator" -> Crankk toggles to sx1302 (same as with its templates).
  let m=(process.env.MODEL||"").toLowerCase(),v=(process.env.VARIANT||process.env.MODEL_VARIANT||"").toLowerCase(),rg=process.env.REGION||"EU868";
  if(m==="panther"&&v==="x2")m="panther_x2";
  const cand=["./config/"+m+"/sx1301/global_conf.json."+rg,"./v2/sx1301/global_conf.json."+rg];
  let s1=null,s1src=null;
  for(const f of cand){const t=read(f);if(t){try{const jj=JSON.parse(strip(t));if(jj.SX1301_conf){s1=jj.SX1301_conf;s1src=f;break;}}catch(e){}}}
  if(!s1){out(Object.assign(info,{error:"no SX1301 template found for fallback block",cand}));process.exit(4);}
  if(!a.j.SX1301_conf){const o={};for(const k of Object.keys(a.j)){o[k]=a.j[k];if(k==="SX130x_conf")o.SX1301_conf=s1;}a.j=o;}
  const txt=JSON.stringify(a.j,null,4)+"\n";
  let backup=null;
  if(custom&&!info.custom_is_paul){backup=CUSTOM+".before-paul-lut-"+ts;fs.writeFileSync(backup,custom);}
  fs.writeFileSync(CUSTOM+".tmp",txt);fs.renameSync(CUSTOM+".tmp",CUSTOM);
  fs.writeFileSync(STATE,JSON.stringify({marker:"PAUL_CRANKK_SAFE_LUT_V1",ts,sha256:sha(txt),backup:backup||(st&&st.backup)||null,old_lut:old,new_lut:PAUL},null,1));
  out(Object.assign(info,{result:"written",old_lut:lutStr(old),new_lut:lutStr(PAUL),backup,sx1301_block:s1src}));process.exit(0);
}
if(mode==="uninstall"){
  if(!st){out(Object.assign(info,{result:"not installed"}));process.exit(0);}
  if(custom&&sha(custom)!==st.sha256){out(Object.assign(info,{error:"/data/global_conf.json changed since install - left alone"}));process.exit(5);}
  if(st.backup&&read(st.backup)!==null){fs.copyFileSync(st.backup,CUSTOM);}else if(custom){fs.unlinkSync(CUSTOM);}
  fs.renameSync(STATE,STATE+".removed-"+ts);
  out(Object.assign(info,{result:"removed",restored_backup:st.backup||null}));process.exit(0);
}
out({error:"bad mode"});process.exit(2);
'
js() { $D exec -w /home/node/app "$C" node -e "$JS" "$1" "$TS"; }

restart_and_verify() {
  # only the log since the last "npm start" counts (docker logs --since is unreliable on some boxes)
  $D restart "$C" >/dev/null || return 1
  i=0; up=0; logs=""
  while [ $i -lt "$WAIT" ]; do
    sleep 10; i=$((i+10))
    # fallback when the docker json log is corrupt (unclean shutdown -> "Error grabbing logs"):
    # forwarder process alive in 3 consecutive checks (30 s) = concentrator running (a failed start exits within seconds)
    if $D exec "$C" sh -c 'grep -qx "crankk-pktfwd" /proc/[0-9]*/comm 2>/dev/null'; then up=$((up+1)); else up=0; fi
    raw=$($TO $D logs --tail 600 "$C" 2>&1) || raw="$raw
Error grabbing logs: docker logs failed or timed out"
    if echo "$raw" | grep -q "Error grabbing logs"; then
      if [ $up -ge 3 ]; then say "note: docker log unreadable - verified via stable forwarder process instead"; return 0; fi
      continue
    fi
    logs=$(echo "$raw" | awk '/crankk-pktfwd@[0-9.]+ start/{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}')
    if echo "$logs" | grep -qiE "concentrator started|packet can now be received"; then
      echo "$logs" | grep -qiE "failed to start the concentrator" && say "note: SX1301 attempt failed first, Crankk switched to sx1302 (expected)"
      return 0
    fi
    # stopped without a retry pending -> fail fast
    if echo "$logs" | grep -qE "does not contain a JSON object named (SX1301_conf|SX130x_conf)|No config file found"; then
      echo "$logs" | tail -8; return 1
    fi
  done
  echo "$logs" | tail -25
  return 1
}

detached() {
  # Meshpoint nodes run crankk-pktfwd DETACHED (mux only, no lora_pkt_fwd): nothing to fix there
  $D exec "$C" sh -c 'grep -qx "crankk-pktfwd" /proc/[0-9]*/comm 2>/dev/null' && return 1
  return 0
}

case "$MODE" in
  --check|--status)
    js "${MODE#--}"
    detached && say "WARNING: no crankk-pktfwd process in $C (detached/Meshpoint or stopped) - LUT would not matter"
    ;;
  --apply)
    if [ -z "${PAUL_LUT_BG:-}" ]; then
      # run detached so a dropped ssh session can never interrupt verify/rollback
      L=/tmp/paul-lut-apply.log; [ -w /data ] && L=/data/paul-lut-apply.log
      PAUL_LUT_BG=1 nohup sh "$0" --apply > "$L" 2>&1 < /dev/null &
      say "started in background (pid $!), log $L"
      while kill -0 $! 2>/dev/null; do sleep 5; done
      cat "$L"; grep -q "OK: PAUL LUT active\|already active" "$L"; exit $?
    fi
    detached && die "no packet forwarder process running in $C (detached/Meshpoint?) - skipped" 6
    res=$(js apply) || { echo "$res"; die "apply refused"; }
    echo "$res"
    echo "$res" | grep -q '"result":"already"' && { say "PAUL LUT already active - nothing to do"; exit 0; }
    say "restarting $C with PAUL LUT (wait up to ${WAIT}s for 'concentrator started')"
    if restart_and_verify; then
      chk=$(js check); echo "$chk"
      if echo "$chk" | grep -q '"paul_lut_active":true'; then say "OK: PAUL LUT active ($TS)"; exit 0; fi
      say "running config does not show PAUL LUT"
    fi
    say "ROLLBACK: concentrator did not start or LUT not active"
    js uninstall
    restart_and_verify && say "rollback done, original config running" || say "rollback restart ALSO failed - check manually"
    exit 7
    ;;
  --uninstall)
    js uninstall || exit 5
    restart_and_verify && say "original Crankk config running again" || die "restart after uninstall not confirmed"
    ;;
  *) die "usage: $0 --check|--apply|--uninstall|--status" 2 ;;
esac
