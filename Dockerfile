FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETARCH
COPY --chmod=0755 linux-${TARGETARCH}/graphwan /usr/local/bin/graphwan
ENTRYPOINT ["/usr/local/bin/graphwan"]
CMD ["server", "--listen=0.0.0.0:8443", "--data-dir=/data"]
EXPOSE 8443
