# Phoenix IMG4 Parser

Read-only structural parser for Apple's IMG4-family containers. Requires Python 3.10+ and uses only the standard library.

## Supported structures

- IMG4: outer container; reports embedded IM4P, IM4M and IM4R sequences.
- IM4P: reads payload type, description, OCTET STRING offset/length and optionally payload SHA-256.
- IM4M / IM4R: reports field boundaries without interpreting cryptographic or restore semantics.

## Usage

    python3 tools/phoenix-img4/phoenix_img4.py path/to/component.im4p
    python3 tools/phoenix-img4/phoenix_img4.py path/to/component.im4p --hash-payload --out reports/component.json

Run tests:

    python3 -m unittest discover -s tools/phoenix-img4/tests -v

## Parser behavior

- Parses definite-length DER TLVs with bounds checks.
- Rejects indefinite-length BER, non-minimal DER lengths, unsupported high-tag-number form, malformed nesting and trailing bytes.
- Does not write extracted payloads.
- Does not decrypt IMG4, validate signatures, verify manifests, patch firmware or contact a device.
- --hash-payload hashes raw OCTET STRING bytes; it is not a signature check.

## Known limitations

This is an initial structural parser, not a complete Apple IMG4 implementation. Real firmware may contain optional fields or encoding variants requiring more fixtures. Validate against known-good public samples and reference project files before relying on output. Keep proprietary firmware local; do not commit it.
