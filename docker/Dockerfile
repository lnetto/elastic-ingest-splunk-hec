# Elasticsearch with the Splunk HEC plugin baked in.
#   docker build -f docker/Dockerfile -t elasticsearch-ingest-splunk-hec:9.5.4 .
ARG STACK_VERSION=9.5.4
FROM docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
ARG STACK_VERSION
COPY --chown=elasticsearch:root dist/ingest-splunk-hec-*-es${STACK_VERSION}.zip /tmp/ingest-splunk-hec.zip
RUN bin/elasticsearch-plugin install --batch file:///tmp/ingest-splunk-hec.zip \
    && rm /tmp/ingest-splunk-hec.zip
