#!/usr/bin/env bash
# pasu-egress self-guard demo.
#
# Runs pasu-egress inside a single privileged container, attached to the
# container's OWN cgroup (default-deny, allow only 1.1.1.1), then proves that
# the kernel drops egress the policy doesn't allow — regardless of the app.
#
# Requires: Linux host with cgroup v2, a kernel with BPF cgroup support, and
# an image built from deploy/Dockerfile (default tag: pasu-egress:latest).
#
#   ./deploy/demo.sh                 # uses pasu-egress:latest
#   IMAGE=pasu-egress:dev ./deploy/demo.sh
set -euo pipefail

IMAGE="${IMAGE:-pasu-egress:latest}"
ALLOW_IP="${ALLOW_IP:-1.1.1.1}"      # allowed destination
BLOCK_IP="${BLOCK_IP:-1.0.0.1}"      # not in the allowlist -> must be dropped

echo "== pasu-egress self-guard demo (image: $IMAGE) =="
echo "   allow=$ALLOW_IP  block=$BLOCK_IP"

docker run --rm --privileged \
  --name pasu-selfguard-demo \
  --entrypoint /bin/sh \
  -e ALLOW_IP="$ALLOW_IP" -e BLOCK_IP="$BLOCK_IP" \
  "$IMAGE" -c '
    set -u
    # Attach default-deny to this container'"'"'s own cgroup; allow only $ALLOW_IP.
    pasu-egress --cgroup-path /sys/fs/cgroup --allow "$ALLOW_IP" &
    PASU=$!
    sleep 3

    probe() {  # $1=ip  -> prints reachable|dropped
      if curl -sS --max-time 6 -o /dev/null "http://$1" 2>/dev/null; then echo reachable; else echo dropped; fi
    }

    A=$(probe "$ALLOW_IP")
    B=$(probe "$BLOCK_IP")
    kill $PASU 2>/dev/null || true

    echo "  allowed  $ALLOW_IP -> $A"
    echo "  blocked  $BLOCK_IP -> $B"
    if [ "$A" = reachable ] && [ "$B" = dropped ]; then
      echo "RESULT: PASS (kernel enforced the allowlist)"; exit 0
    else
      echo "RESULT: FAIL"; exit 1
    fi
  '
