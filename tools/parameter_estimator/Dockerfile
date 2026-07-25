ARG SAGE_IMAGE=sagemath/sagemath
ARG SAGE_DIGEST
FROM ${SAGE_IMAGE}@${SAGE_DIGEST}

USER root
ARG LATTICE_ESTIMATOR_COMMIT=3e48ef421ec256afddb3e7d2249a77eab6e9ba12
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
