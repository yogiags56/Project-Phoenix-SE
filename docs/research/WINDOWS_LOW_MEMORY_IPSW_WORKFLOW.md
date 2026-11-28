# Windows Low-Memory IPSW Research Workflow

Profile: Windows 10/11, 8 GB RAM, Python 3.12 x64.

Purpose: inspect large Target and Donor IPSWs locally without uploading firmware or extracting both archives in full. This workflow does not decrypt IMG4/IM4P, decompress kernelcache payloads, patch, sign, restore, or boot firmware.

## 1. Storage layout

Use a drive with sufficient free space. SSD is preferred.

~~~text
D:\PhoenixSE\
  firmware\target\target.ipsw
  firmware\donor\donor.ipsw
  workspace\target\
  workspace\donor\
  tools\
  reports\target\
  reports\donor\
  reports\comparison\
  handoff\
  logs\
~~~

Keep IPSW originals immutable. Do not unpack both IPSWs into full directory trees. Extract only the specific member needed for the next analysis step.

## 2. Install baseline tools

Install Python 3.12 x64, Git for Windows, and the Windows ipsw binary from the official blacktop/ipsw GitHub Releases page. 7-Zip is optional for manual archive inspection.

~~~powershell
python --version
python -c "import struct; print(struct.calcsize('P') * 8, 'bit')"
git --version
ipsw version
~~~

Create a project-local Python environment:

~~~powershell
Set-Location D:\PhoenixSE
python -m venv .venv
$PY = "D:\PhoenixSE\.venv\Scripts\python.exe"
& $PY --version
~~~

The existing Phoenix evidence scripts use Python's standard library. Avoid installing large dependency stacks unless a specific analyzer requires them.

## 3. Clone or update Phoenix source

~~~powershell
Set-Location D:\PhoenixSE
git clone https://github.com/yogiags56/Project-Phoenix-SE.git source
# On later updates:
Set-Location D:\PhoenixSE\source
git pull --ff-only
git rev-parse HEAD | Tee-Object D:\PhoenixSE\logs\phoenix-source-commit.txt
~~~

## 4. Preflight the two IPSWs

Set the actual local paths:

~~~powershell
$Target = "D:\PhoenixSE\firmware\target\target.ipsw"
$Donor  = "D:\PhoenixSE\firmware\donor\donor.ipsw"
Get-Item $Target, $Donor | Select-Object FullName, Length
Get-PSDrive D
~~~

Do not put ECID, serial number, UDID, IMEI, or other personal device identifiers in research filenames or reports.

## 5. Inventory kernelcache member names

Do not assume a kernelcache filename from another iPhone model or iOS build. List candidates from each IPSW:

~~~powershell
$ListMembers = @'
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, "r") as z:
    for i in z.infolist():
        n = i.filename.lower()
        if "kernelcache" in n or n.endswith("buildmanifest.plist"):
            print(f"{i.filename}\tcompressed={i.compress_size}\tuncompressed={i.file_size}")
'@

$ListMembers | & $PY - $Target
$ListMembers | & $PY - $Donor
~~~

Save outputs separately. Confirm one root BuildManifest.plist. Select the kernelcache by exact basename only after reviewing the listing. If duplicate basenames exist, stop and resolve ambiguity rather than guessing.

## 6. Run Phoenix IPSW Evidence Inspector one firmware at a time

The inspector streams IPSW SHA-256 and selected ZIP-member hashing in 1 MiB chunks. It reads the BuildManifest plist and can optionally extract one selected kernelcache member. It does not decode the IM4P payload.

Target example (replace the member name with the exact basename from step 5):

~~~powershell
Set-Location D:\PhoenixSE\source
$TargetArgs = @(
  "tools\phoenix-evidence\phoenix_evidence.py", $Target,
  "--kernelcache", "EXACT_TARGET_KERNELCACHE_BASENAME",
  "--extract-kernelcache", "D:\PhoenixSE\workspace\target\kernelcache.im4p",
  "--out", "D:\PhoenixSE\reports\target\ipsw-evidence.json"
)
& $PY @TargetArgs
~~~

Donor example:

~~~powershell
$DonorArgs = @(
  "tools\phoenix-evidence\phoenix_evidence.py", $Donor,
  "--kernelcache", "EXACT_DONOR_KERNELCACHE_BASENAME",
  "--extract-kernelcache", "D:\PhoenixSE\workspace\donor\kernelcache.im4p",
  "--out", "D:\PhoenixSE\reports\donor\ipsw-evidence.json"
)
& $PY @DonorArgs
~~~

Important:
- The inspector requires exactly one matching member for the requested basename. Ambiguity is an intentional stop condition.
- It records supported product types and build version from BuildManifest, member identity, sizes and SHA-256 values.
- The ZIP-member hash is over bytes after ZIP decompression. It is not the hash of a later decrypted/decompressed kernelcache.
- Stop if the reported product/build identity does not match the expected firmware.
- Do not use the default kernelcache name blindly.

## 7. Payload triage: critical RAM warning

The current tools/phoenix-payload/phoenix_payload.py implementation reads its entire input into memory. On an 8 GB machine, do not feed it a large kernelcache or multi-gigabyte payload. This may exhaust RAM or cause heavy paging.

Use it only for small selected payloads whose sizes have been checked first. For large kernelcache files, preserve them locally and defer deep parsing until a streaming/seek-based payload inspector exists. Other analyzers may also load complete inputs; inspect their source before passing large files.

## 8. Low-memory operating rules

1. Process Target first, then close the process before starting Donor.
2. Never extract both full IPSW filesystems at once.
3. Avoid GUI hex editors that load large binaries completely into RAM.
4. Keep one large payload operation active at a time.
5. Prefer streaming hashes and archive-member inspection.
6. Check actual member sizes before extraction.
7. Keep reasonable free disk space for Windows paging and temporary files.
8. Do not disable the Windows page file.
9. Record command lines, timestamps, tool versions, Phoenix source commit, input hashes and output hashes.
10. If a parser requires a full in-memory byte array, defer it until a streaming or memory-mapped implementation is available.

## 9. First evidence handoff

Initially share only Target and Donor ipsw-evidence.json reports, their kernelcache member listings, and a text file with Python, ipsw, Git and Phoenix commit versions.

Do not upload IPSWs, raw kernelcache files, decrypted firmware, private keys, or full device logs.

After creating a manifest listing only these small reports, build a ZIP:

~~~powershell
$BundleArgs = @(
  "tools\phoenix-evidence-bundle\phoenix_evidence_bundle.py",
  "D:\PhoenixSE\handoff\manifest.json",
  "--out", "D:\PhoenixSE\handoff\phoenix-first-handoff.zip",
  "--max-file-mb", "2", "--max-total-mb", "10"
)
& $PY @BundleArgs
~~~

Inspect the ZIP contents and manually review every report for identifiers before sharing. Automated identifier detection is not a complete privacy audit.

## 10. Acceptance gate before deeper analysis

Do not begin target/donor kernel compatibility comparison until Target and Donor ProductType, ProductVersion and ProductBuildVersion are recorded from their own BuildManifest; IPSW SHA-256 values and exact kernelcache member names are recorded; uncompressed ZIP-member hashes and sizes are recorded; every report is tied to the Phoenix source commit and tool version; and no identity or provenance ambiguity remains.

Passing this gate establishes traceable inputs only. It does not prove A9/A13 kernel, driver, restore, or boot compatibility.

## 11. Engineering gaps identified

- Add a streaming ZIP member inventory/export command to Phoenix.
- Add BuildManifest expected-ProductType validation.
- Add streaming/seek-based IMG4 and payload inspection. The current Payload Inspector uses read_bytes() and is unsuitable for large files on an 8 GB system.
- Add memory-aware preflight checks and maximum input-size policies to analyzers that load whole files.
- Add automated report-manifest generation with input/output hashes and tool commit metadata.
- Add Windows CI to run standard-library unit tests.

Until implemented and tested, these stages remain pending.