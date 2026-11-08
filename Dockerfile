# Build image for BUILD_MODE=docker (spec §4.2).
# Keep the project package list in sync with .devcontainer/Dockerfile.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nasm \
    make \
    binutils \
    gdb \
    python3 \
    python3-pytest \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["bash"]
