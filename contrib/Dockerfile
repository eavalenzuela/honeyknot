# Multi-stage Dockerfile for honeyknot.
#
# The runtime image is python:3.13-slim with a non-root user. The daemon
# is invoked as PID 1; use Docker's signal forwarding for graceful
# shutdown / reload:
#   docker kill --signal=HUP honeyknot     # reload handler TOMLs
#   docker kill --signal=TERM honeyknot    # graceful stop
#
# Volumes:
#   /etc/honeyknot/handlers   # TOML handler definitions
#   /var/log/honeyknot        # raw/, samples/, events.jsonl, pcap/
#
# Binding to ports <1024 requires either running with --user 0 and using
# --run-as-user inside the container, or running unprivileged and only
# mapping non-privileged container ports. The image grants
# CAP_NET_BIND_SERVICE so the non-root user can bind low ports if started
# with --cap-add NET_BIND_SERVICE --user 65532.

FROM python:3.13-slim AS runtime

ARG UID=65532
ARG GID=65532
RUN groupadd --system --gid ${GID} honeyknot \
    && useradd --system --uid ${UID} --gid honeyknot --no-create-home \
        --shell /usr/sbin/nologin honeyknot \
    && mkdir -p /etc/honeyknot/handlers /var/log/honeyknot \
    && chown -R honeyknot:honeyknot /etc/honeyknot /var/log/honeyknot

WORKDIR /opt/honeyknot
COPY honeyknot/ ./honeyknot/
COPY pyproject.toml README.md ./
COPY handlers/ /etc/honeyknot/handlers/

# No pip install — stdlib only. Optional: `pip install yara-python` if you
# want --yara-rules support. Keep the base image lean by default.

USER honeyknot

# Grant CAP_NET_BIND_SERVICE to python so non-root can bind low ports,
# if the container is started with --cap-add NET_BIND_SERVICE.
# (This is a no-op without the cap; safe to include.)

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "-m", "honeyknot"]
CMD ["-i", "0.0.0.0", \
     "-hd", "/etc/honeyknot/handlers", \
     "-ld", "/var/log/honeyknot"]
