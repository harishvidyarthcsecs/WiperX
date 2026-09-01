# wiperx/Dockerfile
#
# WiperX web application container. Note the fundamental constraint that
# does NOT go away just because this runs in a container: wiping a real
# disk needs root and direct access to /dev block devices. That means the
# `web` service here must run with --privileged (or a scoped --device
# grant per host disk) and host PID/network as needed for your deployment
# - see docker-compose.yml's comments. The forensic-carving and
# file-eraser modules do not need this: they operate on ordinary files
# and don't require privileged access.
FROM python:3.13-slim AS base

# System packages the app shells out to or links against:
#   sleuthkit    -> pytsk3 / Module 3 filesystem-aware undelete
#   testdisk     -> optional companion recovery tool referenced in docs
#   libmagic1    -> python-magic classification (Module 3)
#   nvme-cli     -> LinuxNVMeWipeStrategy (Module 1)
#   hdparm       -> LinuxHdparmSecureEraseStrategy (Module 1, ATA Secure Erase)
#   util-linux   -> lsblk/blkdiscard (disk_scanner.py, LinuxSSDWipeStrategy)
#   e2fsprogs    -> mkfs.ext4/debugfs, used by tools/demo_recover.sh
#   build-essential/python3-dev -> some pinned wheels (e.g. psutil) have no
#                                  prebuilt wheel for this arch and compile
#                                  from source; confirmed needed by a real
#                                  `docker build` in this repo, not assumed
RUN apt-get update && apt-get install -y --no-install-recommends \
        sleuthkit testdisk libmagic1 nvme-cli hdparm util-linux e2fsprogs \
        openssh-client build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The web UI stylesheet (web/static/css/app.css) is a committed build artifact
# produced by `npm run build:css` (Tailwind). Node is a dev-only dependency and
# is deliberately NOT installed in the runtime image; rebuild and commit the CSS
# on the host when templates change (CI verifies it is current).

# reports/, logs/, cases/, keys/ are runtime state - mounted as volumes in
# docker-compose.yml so they survive a container recreate. Create them here
# too so `docker run` without compose still works.
RUN mkdir -p reports logs cases keys

EXPOSE 5000

# Default: production WSGI server. Override the command for `python run.py`
# during development (see docker-compose.yml's `web` service comment).
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "120", "run:create_app()"]
