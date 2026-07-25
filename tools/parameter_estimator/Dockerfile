# The digest is supplied by image.lock in CI/release automation. Keeping the
# image reference separate prevents a mutable tag from becoming a security
# input by accident.
ARG SAGE_IMAGE=sagemath/sagemath
ARG SAGE_DIGEST
FROM ${SAGE_IMAGE}@${SAGE_DIGEST}

ARG LATTICE_ESTIMATOR_COMMIT=3e48ef421ec256afddb3e7d2249a77eab6e9ba12
RUN git clone https://github.com/malb/lattice-estimator.git /opt/lattice-estimator \
  && cd /opt/lattice-estimator \
  && git checkout ${LATTICE_ESTIMATOR_COMMIT}
WORKDIR /workspace
COPY inputs /workspace/inputs
COPY run.sh /workspace/run.sh
ENTRYPOINT ["/workspace/run.sh"]
