ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Set service to be run
ENV SERVICE_PATH pdf_id.pdf_id.PDFId

# There should be no dependancies to install according to the installer.py

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy PEFile service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
