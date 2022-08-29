# Usage:
#  DOCKER_BUILDKIT=1 docker build -t lsf .
#  docker run -it --rm --security-opt seccomp=unconfined lsf uname -a

# Hints:
# * Retry `docker run` several times if you see `Error: input/output error`
# * Use `docker run -e LSF_DEBUG=1` to enable debug output

ARG FREEBSD_VERSION=13.1
ARG GOLANG_VERSION=1.19

FROM golang:${GOLANG_VERSION}-alpine AS work
RUN apk add --no-cache curl git make

FROM work AS build
WORKDIR /src
COPY . .
RUN --mount=target=/root/.cache,type=cache \
  make && mv _output /out

FROM work AS download-freebsd
ARG FREEBSD_VERSION
RUN mkdir -p /freebsd/rootfs && \
  curl -SL http://ftp.freebsd.org/pub/FreeBSD/releases/amd64/${FREEBSD_VERSION}-RELEASE/base.txz | xzcat | tar x -C /freebsd/rootfs

FROM scratch
COPY --from=download-freebsd /freebsd/rootfs/ /
COPY --from=build /out/bin/lsf /lsf
WORKDIR /
ENV LSF_DEBUG=0
ENTRYPOINT ["/lsf", "--"]
CMD ["/bin/sh"]
