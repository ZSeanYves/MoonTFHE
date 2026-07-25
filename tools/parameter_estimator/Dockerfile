ARG SAGE_BASE=sagemath/sagemath@sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667
FROM ${SAGE_BASE}

USER root
ARG LATTICE_ESTIMATOR_COMMIT=3e48ef421ec256afddb3e7d2249a77eab6e9ba12
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git \
  && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/malb/lattice-estimator.git /opt/lattice-estimator \
  && cd /opt/lattice-estimator \
  && git checkout ${LATTICE_ESTIMATOR_COMMIT} \
  && test "$(git rev-parse HEAD)" = "${LATTICE_ESTIMATOR_COMMIT}" \
  && rm -rf /opt/lattice-estimator/.git
WORKDIR /workspace
COPY inputs /workspace/inputs
COPY estimate.py /workspace/estimate.py
COPY entrypoint.sh /workspace/entrypoint.sh
RUN chmod 0555 /workspace/entrypoint.sh /workspace/estimate.py
USER sage
ENV PYTHONPATH=/opt/lattice-estimator
ENTRYPOINT ["/workspace/entrypoint.sh"]
