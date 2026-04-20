# syntax=docker/dockerfile:1.7

# ============================================================
# PyGuard production image.
#
# Why this is non-trivial: the /api/obfuscate route compiles the
# interpreter + stage1 + stage2 per CPython minor so stubs fail-close
# on version mismatch (v5 contract: target-CPython-minor-specific).
# The runtime image therefore needs python3.9..python3.14 available
# at $PATH, not just at build time.
# ============================================================

# -------------------- builder (Node + any python3) --------------------
FROM node:20-bookworm-slim AS builder

WORKDIR /app

# `npm run prebuild` -> `gen:v5` shells out to `python3` to regenerate
# lib/v5/interpreter_src.ts and lib/v5/build_ir_src.ts. Any python3 works
# here — these bundles are version-agnostic.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build \
 && npm prune --omit=dev


# -------------------- runner (Ubuntu + deadsnakes) --------------------
FROM ubuntu:24.04 AS runner

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

# Node 20 from NodeSource + Python 3.9..3.14 from deadsnakes.
RUN set -eux \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg software-properties-common \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && add-apt-repository -y ppa:deadsnakes/ppa \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      nodejs \
      python3.9 python3.10 python3.11 python3.12 python3.13 python3.14 \
 && apt-get purge -y --auto-remove curl gnupg software-properties-common \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

WORKDIR /app

# Runtime file dependencies:
#   lib/v5/build_ir.py        — spawned by /api/obfuscate
#   lib/v5/transform_ast.py   — imported by build_ir.py
#   lib/v5/runtime_interp.py  — referenced only by measure scripts; not needed
#   scripts/multi_marshal.mjs — imported by the route handler (bundled, but
#                                multi_marshal itself references build_ir.py
#                                at a $PWD-relative path, so we still need
#                                scripts/ present)
COPY --from=builder /app/.next          ./.next
COPY --from=builder /app/node_modules   ./node_modules
COPY --from=builder /app/package*.json  ./
COPY --from=builder /app/public         ./public
COPY --from=builder /app/lib            ./lib
COPY --from=builder /app/scripts        ./scripts

# Optional knob: pin the discovered Python toolchains explicitly.
# Empty by default → discoverPythons() probes $PATH for python3.9..3.14.
ENV PYGUARD_PYTHON_BINS=""

EXPOSE 3000

# `next start` serves both the static site and /api/obfuscate.
CMD ["npm", "run", "start"]
