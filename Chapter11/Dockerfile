# This Dockerfile was created for use with Learning Python for
#   Forensics, Second Edition. It is intended to configure the
#   environment to run the PST Indexing script.

# Install tested base image
FROM ubuntu:18.04

# Create and navigate to working directory
RUN ["mkdir", "/opt/book"]
WORKDIR /opt/book

# Install Dependencies
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "python-dev", "python-pip", "lighttpd"]
EXPOSE 80/tcp

# Copy across the libpff and pypff built library, v. 20180812, fecb691
COPY --chown=root:root docker_libs/ /
RUN ["ldconfig"]

# Copy across scripts
COPY "pst_indexer.py" "/opt/book"
COPY "stats_template.html" "/opt/book"

# Pip install tested dependency versions
RUN ["pip", "install", "unicodecsv==0.14.1", "jinja2==2.10"]