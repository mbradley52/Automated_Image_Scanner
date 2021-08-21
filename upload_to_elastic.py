from elasticsearch import Elasticsearch
import os
import datetime
from datetime import date
import json

# Sends payloads to ElasticSearch cluster
def send_to_es(payload):

    # Create scan date
    scan_date = str(datetime.datetime.now())
    scan_date = scan_date.replace(" ", "T")
    payload["uploadTime"] = scan_date

    # Create index name
    index_date = scan_date.split("T")
    index = "scan-files-" + index_date[0]

    # Configure host
    es = Elasticsearch(
        [{"host": "localhost", "port": 9200}], http_auth=("elastic", "changeme")
    )
    # print(es.ping())
    response = es.index(index=index, body=payload)
    # print(payload)
    # print(response)


def trivy_create_payload(vulnerability, file_name):

    payload = {}

    payload["scanner"] = "Trivy"
    payload["vulnerability_name"] = vulnerability["VulnerabilityID"]
    # Normalize severity value
    if vulnerability["Severity"] == "CRITICAL":
        payload["severity"] = "Critical"
    elif vulnerability["Severity"] == "HIGH":
        payload["severity"] = "High"
    elif vulnerability["Severity"] == "MEDIUM":
        payload["severity"] = "Medium"
    elif vulnerability["Severity"] == "LOW":
        payload["severity"] = "Low"
    else:
        payload["severity"] = "Unknown"
    payload["component"] = vulnerability["PkgName"]
    try:
        payload["cvssScore"] = vulnerability["CVSS"]["nvd"]["V2Score"]
    except:
        # do nothing
        pass
    payload["cve"] = vulnerability["VulnerabilityID"]
    try:
        payload["cwe"] = vulnerability["CweIDs"][0]
    except:
        payload["cwe"] = "missing"
    try:
        payload["publicationTime"] = vulnerability["PublishedDate"]
    except:
        # do nothing
        pass
    try:
        payload["imageCreationTime"] = vulnerability["LastModifiedDate"]
    except:
        # do nothing
        pass
    return payload


def trivy(date_prefix):
    count = 0

    trivy_path = (
        "/home/linux/Desktop/Automated_Image_Scanner/trivy_Output/"
        + date_prefix
        + "_trivy_artifacts"
    )
    trivy_files = os.listdir(trivy_path)

    # Loop over Trivy files, construct payload, send to ES
    for file in trivy_files:
        # Get file contents
        f = open(trivy_path + "/" + file)
        scanOutput = json.load(f)

        # Get each finding in the file
        for target in scanOutput:

            if "Vulnerabilities" in target.keys():
                for vulnerability in target["Vulnerabilities"]:
                    count = count + 1
                    # Construct payload
                    payload = trivy_create_payload(vulnerability, file)
                    # Send payload
                    send_to_es(payload)

    print("finished sending {0} Trivy payloads".format(count))


def grype_create_payload(vulnerability, file_name):
    payload = {}

    payload["scanner"] = "grype"
    payload["vulnerability_name"] = vulnerability["vulnerability"]["id"]
    # Don't have to normalize severity as this is the chosen form
    payload["severity"] = vulnerability["vulnerability"]["severity"]
    payload["component"] = vulnerability["artifact"]["name"]
    payload["cve"] = vulnerability["vulnerability"]["id"]
    image = file_name.split("_")
    payload["image"] = image[1]

    return payload


def grype(date_prefix):
    count = 0

    grype_path = (
        "/home/linux/Desktop/Automated_Image_Scanner/grype_Output/"
        + date_prefix
        + "_grype_artifacts"
    )
    grype_files = os.listdir(grype_path)

    # Loop over Docker-scan files, construct payload, send to ES
    for file in grype_files:

        # Get file contents
        f = open(grype_path + "/" + file)
        scanOutput = json.load(f)

        # Get each finding in the file
        for vulnerability in scanOutput["matches"]:
            count = count + 1
            # Construct payload
            payload = grype_create_payload(vulnerability, file)
            # Send payload
            send_to_es(payload)

    print("finished sending {0} grype payloads".format(count))


def dockerscan_create_payload(vulnerability, file_name):
    # print(json.dumps(vulnerability))

    payload = {}

    payload["scanner"] = "docker-scan"
    payload["vulnerability_name"] = vulnerability["title"]
    # Normalize severity value
    payload["severity"] = vulnerability["severity"].capitalize()
    payload["component"] = vulnerability["title"]
    try:
        payload["cvssScore"] = vulnerability["cvssScore"]
    except:
        pass
    payload["cve"] = vulnerability["identifiers"]["CVE"]
    payload["cwe"] = vulnerability["identifiers"]["CWE"]
    payload["publicationTime"] = vulnerability["publicationTime"]
    payload["imageCreationTime"] = vulnerability["creationTime"]

    image = file_name.split("_")
    payload["image"] = image[1]

    return payload


def docker_scan(date_prefix):

    count = 0
    dockerscan_path = (
        "/home/linux/Desktop/Automated_Image_Scanner/docker-scan_Output/"
        + date_prefix
        + "_docker-scan_artifacts"
    )

    dockerscan_files = os.listdir(dockerscan_path)

    # Loop over Docker-scan files, construct payload, send to ES
    for file in dockerscan_files:

        # Get file contents
        f = open(dockerscan_path + "/" + file)
        scanOutput = json.load(f)

        # Get each finding in the file
        for vulnerability in scanOutput["vulnerabilities"]:
            count = count + 1

            # Construct payload
            payload = dockerscan_create_payload(vulnerability, file)
            # Send payload
            send_to_es(payload)

    print("finished sending {0} docker-scan payloads".format(count))


def main():

    date_prefix = str(date.today())

    trivy(date_prefix)
    grype(date_prefix)
    docker_scan(date_prefix)


if __name__ == "__main__":
    main()
