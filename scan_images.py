import subprocess
import os
import json


# Process output, return counts
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

    dir = "trivy_Output/"

    # List to hold results
    findingsList = {}

    # Make output directory
    subprocess.run(["mkdir", dir])

    total_criticalCount = 0
    total_highCount = 0
    total_medCount = 0
    total_lowCount = 0
    total_vulnerableComponents = 0

    # for every image in the list, run a scan and output to custom file.
    for image in images:

        print("\nScanning Image: {0}".format(image))

        # Create file name
        fileName = image.split("/")
        outputFile = dir + fileName[0] + "-" + fileName[1] + ".json"

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

    print()
    print("Trivy scanned {0} images and found:".format(len(image)))
    print("\t {0} Vulnerable Components".format(total_vulnerableComponents))
    print("\t {0} Critical Vulnerabilities".format(total_criticalCount))
    print("\t {0} High Vulnerabilities".format(total_highCount))
    print("\t {0} Medium Vulnerabilities".format(total_medCount))
    print("\t {0} Low Vulnerabilities".format(total_lowCount))


if __name__ == "__main__":
    main()
