"""v13.3 stub builder — plaintext VM + chained encrypted programs.

Architecture summary (see also docs/v13_architecture.md):

  * The VM runtime is inlined as PLAINTEXT (per-build diversified).
    There is no `_VMC` blob; the attacker's v13.2-era `compile()`
    correctness-oracle no longer applies because there is nothing
    to compile.

  * Two small ciphertext blobs:
      _PA  = prog_a XOR keystream(master, _NA)     where master = scrypt(pw)
      _PB  = prog_b XOR keystream(key_b, _NB)      where key_b  = state_key(state_after_prog_a)

  * prog_a is a seed-installation program. Run correctly, it leaves
    the first 16 state slots at the known seed values. Run on garbage
    (wrong password → wrong prog_a plaintext), state ends up
    unpredictable, key_b is wrong, prog_b decrypts to further garbage
    and runs to produce no flag-shaped output.

  * prog_b is the flag emitter. Given correct plaintext, it
    re-installs seeds into a fresh state, assembles the FLAG bytes
    into slot 16 via the LDI+XAB-over-zero pattern, resolves `print`
    by hash, calls it.

Per-build randomness: opcode byte values (16 permutations of 0..255)
and the keystream discriminator byte. Both are derived from a
32-byte build seed and baked into the rendered VM source literally.
"""
from __future__ import annotations
import hashlib
import inspect
import os
from pathlib import Path

from . import vm_v13_3 as vm_ref
from . import diversify, pack, bootstrap_v13_3
from . import inner_program_v13_3 as ip3


DEFAULT_PASSWORD = b"correcthorse"
NSTATE = 64
MAX_STEPS = 20000
OUT_LEN = 64   # fixed-length output; closes the output-length oracle.


def _strip_vm_source(source: str) -> str:
    """Remove the docstring, `from __future__` and the `import
    hashlib` (the bootstrap already imports it at the top)."""
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
        if ln.startswith("import hashlib"):
            continue
        out.append(ln)
    return "\n".join(out)


def _state_after_prog_a(prog_a_bytes: bytes, profile: "diversify.BuildProfile",
                        master: bytes, salt: bytes, nstate: int) -> list:
    """Compute state_a by running prog_a with the inner-scrypt result
    injected into state[20] via init_slots (matching what the
    bootstrap will do at run time).

    v13.3.2: prog_a is a no-op (HLT-only). The 'chain work' is the
    bootstrap's unconditional inner scrypt. The builder must mirror
    the bootstrap exactly — same pw_in/salt_in derivation, same
    scrypt params, same init_slots — so state_a here equals state_a
    at run time.
    """
    base_src = inspect.getsource(vm_ref)
    stripped = _strip_vm_source(base_src)
    rendered = diversify.render_vm_source_v13_3(profile, stripped)
    ns: dict = {"__name__": "__builder_vm__", "hashlib": hashlib}
    exec(rendered, ns)
    run = ns["run"]
    # v13.3.3 F4: mix the public build salt into the inner-scrypt pw/salt
    # derivation, mirroring the bootstrap exactly.
    pw_in = hashlib.sha256(master + salt + b"v13_3_3_pa_pw").digest()[:16]
    salt_in = hashlib.sha256(master + salt + b"v13_3_3_pa_salt").digest()[:16]
    inner = hashlib.scrypt(pw_in, salt=salt_in,
                           n=pack.SCRYPT_N, r=pack.SCRYPT_R,
                           p=pack.SCRYPT_P, dklen=pack.SCRYPT_DKLEN)
    # v13.3.3 F5: empty VM scope — prog_a is HLT-only so scope is never
    # consulted, but we mirror the bootstrap exactly for symmetry.
    return run(prog_a_bytes, {},
               nstate=nstate, max_steps=MAX_STEPS,
               init_slots={20: inner})


def build(out_path: str | Path, *, password: bytes = DEFAULT_PASSWORD,
          build_seed: bytes | None = None) -> tuple[Path, dict]:
    if build_seed is None:
        build_seed = os.urandom(32)
    profile = diversify.BuildProfile.from_seed(build_seed)

    # 1. Render the per-build VM source (plaintext, diversified).
    base_src = inspect.getsource(vm_ref)
    stripped = _strip_vm_source(base_src)
    rendered_vm_src = diversify.render_vm_source_v13_3(profile, stripped)

    # 2. Assemble prog_a and prog_b with matching opcode values.
    prog_a_ops = ip3.build_prog_a()
    prog_b_ops = ip3.build_prog_b()
    prog_a_bytes = diversify.assemble_diversified(prog_a_ops, profile, nstate=NSTATE)
    prog_b_bytes = diversify.assemble_diversified(prog_b_ops, profile, nstate=NSTATE)

    # 3. Derive master (we need it for both _PA encryption and for
    #    running prog_a to compute state_a).
    salt = pack.random_salt()
    master = pack.derive_master(password, salt)

    # 4. Run prog_a under the same init as the stub will, to compute
    #    the actual state_a. Unlike v13.3, this is NOT analytically
    #    predictable from public constants — state_a depends on
    #    master via the inner OP_SCRYPT in prog_a.
    state_a = _state_after_prog_a(prog_a_bytes, profile, master, salt, NSTATE)

    # 5. Derive key_b = sha256(state_key(state_a) || master). Use the
    #    rendered VM's state_key (opcode values don't matter for
    #    state_key, but we use the same function the stub will use).
    # state_key is identical across builds (no per-build diversification
    # affects it), so we can use the reference module.
    key_b = hashlib.sha256(vm_ref.state_key(state_a) + master).digest()
    nonce_a = pack.random_nonce()
    nonce_b = pack.random_nonce()
    pa_ct = pack.encrypt(prog_a_bytes, master, nonce_a)
    pb_ct = pack.encrypt(prog_b_bytes, key_b, nonce_b)

    # 5. Render the stub.
    stub_src = bootstrap_v13_3.render(
        vm_source=rendered_vm_src,
        salt=salt, nonce_a=nonce_a, nonce_b=nonce_b,
        pa_ct=pa_ct, pb_ct=pb_ct,
        scrypt_n=pack.SCRYPT_N, scrypt_r=pack.SCRYPT_R,
        scrypt_p=pack.SCRYPT_P, scrypt_dklen=pack.SCRYPT_DKLEN,
        flag_slot=ip3.SLOT_FLAG, nstate=NSTATE, max_steps=MAX_STEPS,
        out_len=OUT_LEN,
    )

    out = Path(out_path)
    out.write_text(stub_src)

    meta = {
        "password": password,
        "flag": ip3.FLAG,
        "salt": salt,
        "nonce_a": nonce_a,
        "nonce_b": nonce_b,
        "build_seed": build_seed,
        "opcode_map": profile.opcode_map,
        "discriminator": profile.discriminator,
        "pa_ct_len": len(pa_ct),
        "pb_ct_len": len(pb_ct),
        "key_b": key_b,
    }
    return out, meta


if __name__ == "__main__":
    import sys as _sys
    out = _sys.argv[1] if len(_sys.argv) > 1 else "out_v13_3.py"
    path, meta = build(out)
    size = path.stat().st_size
    print(f"wrote {path} ({size} bytes)")
    print(f"  build seed : {meta['build_seed'].hex()}")
    print(f"  password   : {meta['password']!r}  (for testing)")
    print(f"  flag       : {meta['flag']!r}      (for testing)")
    print(f"  pa_ct_len  : {meta['pa_ct_len']}")
    print(f"  pb_ct_len  : {meta['pb_ct_len']}")
    print(f"  opcode map (NOP→{meta['opcode_map']['NOP']:#04x}, "
          f"LDI→{meta['opcode_map']['LDI']:#04x}, "
          f"XAB→{meta['opcode_map']['XAB']:#04x})")
    print(f"  discriminator: {meta['discriminator']:#04x}")
