import subprocess
import os
import json
from datetime import date
import datetime
import time

# Process output, return counts
def get_scan_date():
    # Generate scan date
    scan_date = str(datetime.datetime.now())
    scan_date = scan_date.replace(" ", "T")

    return scan_date


def trivy_output_processing(scanOutput, image):

    criticalCount = 0
    highCount = 0
    medCount = 0
    lowCount = 0
    vulnerableComponents = 0

    # Enhancements
    # Create json payloads from data
    # Use hashing to ensure counting of unique findings

    # Count
    for target in scanOutput:
        if "Vulnerabilities" in target.keys():
            vulnerableComponents += 1
            for vulnerability in target["Vulnerabilities"]:
                if vulnerability["Severity"] == "CRITICAL":
                    criticalCount += 1

                if vulnerability["Severity"] == "HIGH":
                    highCount += 1

                if vulnerability["Severity"] == "MEDIUM":
                    medCount += 1

                if vulnerability["Severity"] == "LOW":
                    lowCount += 1

    return [vulnerableComponents, criticalCount, highCount, medCount, lowCount]


def trivy_scan(images):

    # Output directory
    dir = "trivy_Output/"
    scanner = "trivy"

    # Make output directory
    subprocess.run(["mkdir", dir])

    # Make directory for current scan:
    date_prefix = str(date.today())
    scan_dir = dir + date_prefix + "_" + scanner + "_artifacts"
    subprocess.run(["mkdir", scan_dir])

    # Count variables
    total_criticalCount = 0
    total_highCount = 0
    total_medCount = 0
    total_lowCount = 0
    total_vulnerableComponents = 0

    start_time = time.time()

    # for every image in the list, run a scan and output to custom file.
    for image in images:

        # Create file name
        print("\nTrivy Scanning: {0}".format(image))

        fileName = image.split("/")
        outputFile = (
            scan_dir + "/" + scanner + "_" + fileName[0] + "-" + fileName[1] + ".json"
        )

        # TODO Logic to obtain return code from scan and skip processing if image failed to download
        # Run trivy command
        subprocess.run(
            ["trivy image -f json -o {0} {1}".format(outputFile, image)], shell=True
        )

        # Process and count vulnerabilities
        f = open(outputFile)
        scanOutput = json.load(f)

        vulns = trivy_output_processing(scanOutput, image)

        total_vulnerableComponents += vulns[0]
        total_criticalCount += vulns[1]
        total_highCount += vulns[2]
        total_medCount += vulns[3]
        total_lowCount += vulns[4]

        total_vulnerabilities = (
            total_criticalCount + total_highCount + total_medCount + total_lowCount
        )

    end_time = time.time()
    total_time = end_time - start_time

    # Generate scan date
    scan_date = get_scan_date()

    # Create Dictionary
    # TODO work in scan speed of each tool - time it takes to scan every image
    scanStats = {}
    scanStats["trivy"] = []
    scanStats["trivy"].append(
        {
            "images_scanned": len(image),
            "total_vuln_components": total_vulnerableComponents,
            "total_vulnerabilities": total_vulnerabilities,
            "Critical_count": total_medCount,
            "high_count": total_highCount,
            "med_count": total_medCount,
            "low_count": total_lowCount,
            "scan_date": scan_date,
            "time_taken": total_time,
        }
    )

    return scanStats


def grype_output_processing(scanOutput, image):

    criticalCount = 0
    highCount = 0
    medCount = 0
    lowCount = 0
    vulnerableComponents = 0

    # Parse json
    for vulnerability in scanOutput["matches"]:
        vulnerableComponents += 1

        if vulnerability["vulnerability"]["severity"] == "Critical":
            criticalCount += 1

        if vulnerability["vulnerability"]["severity"] == "High":
            highCount += 1

        if vulnerability["vulnerability"]["severity"] == "Medium":
            medCount += 1

        if vulnerability["vulnerability"]["severity"] == "Low":
            lowCount += 1

    return [vulnerableComponents, criticalCount, highCount, medCount, lowCount]


def grype_scan(images):

    # Output directory
    dir = "grype_Output/"
    scanner = "grype"

    # Make output directory
    subprocess.run(["mkdir", dir])

    # Make directory for current scan:
    date_prefix = str(date.today())
    scan_dir = dir + date_prefix + "_" + scanner + "_artifacts"
    subprocess.run(["mkdir", scan_dir])

    # Count variables
    total_criticalCount = 0
    total_highCount = 0
    total_medCount = 0
    total_lowCount = 0
    total_vulnerableComponents = 0

    # for every image in the list, run a scan and output to custom file.
    start_time = time.time()
    for image in images:

        # Create file name
        print("\nGrype Scanning: {0}".format(image))

        fileName = image.split("/")
        outputFile = (
            scan_dir + "/" + scanner + "_" + fileName[0] + "-" + fileName[1] + ".json"
        )

        # TODO Logic to obtain return code from scan and skip processing if image failed to download
        # Scan
        subprocess.run(
            ["grype {0} --scope all-layers -o json > {1}".format(image, outputFile)],
            shell=True,
        )

        # Process and count vulnerabilities
        f = open(outputFile)
        scanOutput = json.load(f)

        vulns = grype_output_processing(scanOutput, image)

        total_vulnerableComponents += vulns[0]
        total_criticalCount += vulns[1]
        total_highCount += vulns[2]
        total_medCount += vulns[3]
        total_lowCount += vulns[4]

        total_vulnerabilities = (
            total_criticalCount + total_highCount + total_medCount + total_lowCount
        )

    end_time = time.time()
    total_time = end_time - start_time

    # Generate scan date
    scan_date = str(datetime.datetime.now())
    scan_date = scan_date.replace(" ", "T")

    # Create Dictionary
    # TODO work in scan speed of each tool - time it takes to scan every image
    scanStats = {}
    scanStats[scanner] = []
    scanStats[scanner].append(
        {
            "images_scanned": len(image),
            "total_vuln_components": total_vulnerableComponents,
            "total_vulnerabilities": total_vulnerabilities,
            "Critical_count": total_medCount,
            "high_count": total_highCount,
            "med_count": total_medCount,
            "low_count": total_lowCount,
            "scan_date": scan_date,
            "time_taken": total_time,
        }
    )

    # Write output to json file
    return scanStats


def docker_output_processing(scanOutput, image):

    criticalCount = 0
    highCount = 0
    medCount = 0
    lowCount = 0
    vulnerableComponents = 0

    # Parse json
    for vulnerability in scanOutput["vulnerabilities"]:

        vulnerableComponents += 1

        if vulnerability["severity"] == "critical":
            criticalCount += 1

        if vulnerability["severity"] == "high":
            highCount += 1

        if vulnerability["severity"] == "medium":
            medCount += 1

        if vulnerability["severity"] == "low":
            lowCount += 1

    return [vulnerableComponents, criticalCount, highCount, medCount, lowCount]


def docker_scan(images):

    # Output directory
    dir = "docker-scan_Output/"
    scanner = "docker-scan"

    # Make output directory
    subprocess.run(["mkdir", dir])

    # Make directory for current scan:
    date_prefix = str(date.today())
    scan_dir = dir + date_prefix + "_" + scanner + "_artifacts"
    subprocess.run(["mkdir", scan_dir])

    # Count variables
    total_criticalCount = 0
    total_highCount = 0
    total_medCount = 0
    total_lowCount = 0
    total_vulnerableComponents = 0

    # for every image in the list, run a scan and output to custom file.
    start_time = time.time()
    for image in images:

        # Create file name
        print("\nDocker-scan Scanning: {0}".format(image))

        fileName = image.split("/")
        outputFile = (
            scan_dir + "/" + scanner + "_" + fileName[0] + "-" + fileName[1] + ".json"
        )

        # TODO Logic to obtain return code from scan and skip processing if image failed to download
        # Conduct Docker Scan (image, output file)
        subprocess.run(
            [" docker scan --json {0} > {1}".format(image, outputFile)],
            shell=True,
        )

        # Process and count vulnerabilities
        f = open(outputFile)
        scanOutput = json.load(f)

        vulns = docker_output_processing(scanOutput, image)

        total_vulnerableComponents += vulns[0]
        total_criticalCount += vulns[1]
        total_highCount += vulns[2]
        total_medCount += vulns[3]
        total_lowCount += vulns[4]

        total_vulnerabilities = (
            total_criticalCount + total_highCount + total_medCount + total_lowCount
        )

    end_time = time.time()
    total_time = end_time - start_time

    # Generate scan date
    scan_date = str(datetime.datetime.now())
    scan_date = scan_date.replace(" ", "T")

    # Create Dictionary
    # TODO work in scan speed of each tool - time it takes to scan every image
    scanStats = {}
    scanStats[scanner] = []
    scanStats[scanner].append(
        {
            "images_scanned": len(images),
            "total_vuln_components": total_vulnerableComponents,
            "total_vulnerabilities": total_vulnerabilities,
            "Critical_count": total_medCount,
            "high_count": total_highCount,
            "med_count": total_medCount,
            "low_count": total_lowCount,
            "scan_date": scan_date,
            "time_taken": total_time,
        }
    )

    # Write output to json file
    return scanStats


def main():

    # List of images to scan
    images = [
        "jrrdev/cve-2017-5638:struts-2.3.16.1",
        "vulnerables/cve-2014-6271",
        "vulnerables/cve-2016-7434",
        "vulnerables/cve-2017-7494",
        "vulnerables/cve-2016-10033",
        "knqyf263/cve-2019-6340",
        "vulnerables/cve-2014-0160",
        "co0ontty/cve-2019-3799",
        "vulnerables/cve-2016-6515",
        "npcrowell/cve-2015-3306",
    ]

    run_results = {}
    run_results["Grype"] = grype_scan(images)
    run_results["Trivy"] = trivy_scan(images)
    run_results["Docker-scan"] = docker_scan(images)

    # Generate scan results
    date_prefix = str(date.today())
    stat_file = date_prefix + "_scan_results.json"

    with open(stat_file, "w") as output_file:
        output_file.write(json.dumps(run_results))


if __name__ == "__main__":
    main()
