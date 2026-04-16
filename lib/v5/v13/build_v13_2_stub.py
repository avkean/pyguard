"""v13.2 stub builder — encrypted-VM bootstrap with per-build opcode
permutation.

Outputs a Python file that:

  1. Contains the stage-0 bootstrap (plaintext, ~50 LOC).
  2. Contains two ciphertext blobs — the per-build VM source and the
     assembled program bytes — encrypted under scrypt(password, salt).
  3. Runs: scrypt-derive master key, XOR-decrypt both blobs, exec the
     VM source, call `run(prog, scope)`.
  4. On any failure (wrong password → decrypted VM source is
     non-Python, exec raises; or handlers decode to invalid opcodes),
     emits deterministic pseudo-random hex of fixed length so wrong
     runs are shape-indistinguishable from right runs.

Per-build randomness: the opcode permutation and keystream
discriminator are derived from a random 32-byte build seed, and the
rendered VM source carries the new opcode constants literally. The
assembled program byte stream uses the same opcodes, so an attacker
who recovers the rendered VM source (by paying scrypt cost for one
password guess) can decode the program. An attacker without the
password sees only the outer bootstrap and opaque ciphertext.
"""
from __future__ import annotations
import inspect
import os
from pathlib import Path

from . import vm, inner_program, diversify, pack, bootstrap


# Default test password for the bundled challenge. A real deployment
# would pass this in or read from an environment variable.
DEFAULT_PASSWORD = b"correcthorse"


def _strip_vm_source(source: str) -> str:
    """Remove the module docstring, `from __future__`, and duplicate
    imports (bootstrap already imports hashlib/sys).
    """
    lines = source.splitlines()
    out = []
    in_docstring = False
    for ln in lines:
        if ln.startswith('"""') and not in_docstring:
            in_docstring = True
            if ln.count('"""') >= 2:
                in_docstring = False
            continue
        if in_docstring:
            if ln.endswith('"""'):
                in_docstring = False
            continue
        if ln.startswith("from __future__"):
            continue
        if ln.startswith("import hashlib") or ln.startswith("import sys"):
            continue
        out.append(ln)
    # Prepend imports so the rendered VM source is self-contained when
    # exec'd in an isolated namespace (the bootstrap's imports don't
    # transfer through exec(..., ns)).
    return "import hashlib, sys\n" + "\n".join(out)


def build(out_path: str | Path, *, password: bytes = DEFAULT_PASSWORD,
          build_seed: bytes | None = None) -> tuple[Path, dict]:
    if build_seed is None:
        build_seed = os.urandom(32)
    profile = diversify.BuildProfile.from_seed(build_seed)

    # 1. Render the per-build VM source.
    base_src = inspect.getsource(vm)
    stripped = _strip_vm_source(base_src)
    rendered_vm_src = diversify.render_vm_source(profile, stripped).encode("utf-8")

    # 2. Assemble the inner program with matching opcode values.
    program = inner_program.build_program()
    prog_bytes = diversify.assemble_diversified(program, profile)

    # 3. Encrypt both under scrypt(password, salt).
    salt = pack.random_salt()
    master = pack.derive_master(password, salt)
    nonce_vm = pack.random_nonce()
    nonce_prog = pack.random_nonce()
    vm_ct = pack.encrypt(rendered_vm_src, master, nonce_vm)
    prog_ct = pack.encrypt(prog_bytes, master, nonce_prog)

    # 4. Render the stub.
    stub_src = bootstrap.render(
        salt=salt, nonce_vm=nonce_vm, nonce_prog=nonce_prog,
        vm_ct=vm_ct, prog_ct=prog_ct,
        scrypt_n=pack.SCRYPT_N, scrypt_r=pack.SCRYPT_R,
        scrypt_p=pack.SCRYPT_P, scrypt_dklen=pack.SCRYPT_DKLEN,
    )

    out = Path(out_path)
    out.write_text(stub_src)

    meta = {
        "password": password,
        "flag": inner_program.FLAG,
        "salt": salt,
        "nonce_vm": nonce_vm,
        "nonce_prog": nonce_prog,
        "build_seed": build_seed,
        "opcode_map": profile.opcode_map,
        "discriminator": profile.discriminator,
        "vm_ct_len": len(vm_ct),
        "prog_ct_len": len(prog_ct),
    }
    return out, meta


if __name__ == "__main__":
    import sys as _sys
    out = _sys.argv[1] if len(_sys.argv) > 1 else "out_v13_2.py"
    path, meta = build(out)
    size = path.stat().st_size
    print(f"wrote {path} ({size} bytes)")
    print(f"  build seed : {meta['build_seed'].hex()}")
    print(f"  password   : {meta['password']!r}  (for testing)")
    print(f"  flag       : {meta['flag']!r}      (for testing)")
    print(f"  vm_ct_len  : {meta['vm_ct_len']}")
    print(f"  prog_ct_len: {meta['prog_ct_len']}")
    print(f"  opcode map (NOP→{meta['opcode_map']['NOP']:#04x}, "
          f"LDI→{meta['opcode_map']['LDI']:#04x}, "
          f"XAB→{meta['opcode_map']['XAB']:#04x})")
    print(f"  discriminator: {meta['discriminator']:#04x}")
