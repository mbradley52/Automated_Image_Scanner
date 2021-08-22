# Automated_Image_Scanner

This project was built to evaluate and research three container image vulnerability scanners: AquaSec Trivy, Anchore Grype, and Snyk powered Docker-scan. The two scripts `scan_images.py` & `upload_to_elastic.py` will scan a list of container images against each scanner and then create json payloads from the results to be sent to an Elasticsearch database with Kibana for analysis and visualization creation.

## `scan_images.py`

Automatically scan a list of container images with Trivy, Grype and Snyk powered Docker-scan. All scan results are outputted in json, dated, and saved into an organized directory.

## `upload_to_elastic.py`

Consumes the output from `scan_images.py` to create normalized json payloads that are then uploaded to an Elasticsearch via the python Elasticsearch library. The Elasticsearch database must be running for this script to finish. View the Elasticsearch section for configuring and starting the Elasticsearch database.

## Elasticsearch

The `docker-elk` directory is a containerized version of Elasticsearch configured with docker-compose. <i>Docker is required.</i> Navigate to this directory:

- Run the command `docker-compose up` to start the stack.
- `docker-compose down` or `docker-compose restart` can be used to shutdown or restart the stack.
- The script is configured for the Elasticsearch database created by docker-compose listening at http://Localhost:9200.
