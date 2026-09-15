# Reproducibility image, pinned to linux/amd64 so it runs anywhere: natively on
# x86_64, and on arm64/aarch64 through qemu-user (register it once per boot with
# `docker run --privileged --rm tonistiigi/binfmt --install amd64`).
#
#   docker build --platform linux/amd64 --build-context apps=bench/apps \
#                -t codefix-repro -f bench/repro/Dockerfile .
#   docker run   --platform linux/amd64 --rm codefix-repro
#
# Reproduces: the codefix test suite, the in-process corpus harness, and the SAST
# baselines Bandit, Semgrep and Pysa (bench/baselines.py). Pysa's analysis binary
# (pyre.bin) is x86_64-only, which is why the platform is pinned.
# CodeQL has its own image (bench/repro/codeql.sh); Pysa alone: bench/repro/pysa.sh.
FROM --platform=linux/amd64 python:3.11-slim

RUN pip install --no-cache-dir pytest bandit==1.9.4 semgrep==1.166.0 pyre-check==0.9.25

# Pysa's shipped Flask/Django models only resolve when the app's own libraries are
# importable, so each real app gets a venv whose site-packages is put on Pysa's
# search_path ($PYSA_DEPS/<target>).
# The root .dockerignore drops every `vendor/` dir, so the vendored real apps come
# from the named build context `apps` (= bench/apps).
COPY --from=apps vampi/vendor/requirements.txt /tmp/req/vampi.txt
COPY --from=apps crapi/vendor/services/workshop/requirements.txt /tmp/req/crapi.txt
COPY bench/repro/install_pysa_deps.sh /tmp/req/install_pysa_deps.sh
RUN bash /tmp/req/install_pysa_deps.sh vampi /tmp/req/vampi.txt \
 && bash /tmp/req/install_pysa_deps.sh crapi /tmp/req/crapi.txt
ENV PYSA_DEPS=/opt/pysa-deps

WORKDIR /codefix
COPY . /codefix
COPY --from=apps vampi/vendor /codefix/bench/apps/vampi/vendor
COPY --from=apps crapi/vendor /codefix/bench/apps/crapi/vendor
ENV PYTHONPATH=/codefix/src HOME=/tmp

ENTRYPOINT ["bash", "/codefix/bench/repro/reproduce.sh"]
