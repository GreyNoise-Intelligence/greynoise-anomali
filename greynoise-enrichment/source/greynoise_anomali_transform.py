"""
GreyNoise Anomali ThreatStream Transform Plugin.

This module provides transform functions for enriching IP addresses with GreyNoise intelligence
data within Anomali ThreatStream. It queries the GreyNoise API and creates entities based on
the intelligence gathered about an IP address.

Version: 3.0.0
Author: GreyNoise Intelligence
"""

import os
import sys

import requests
from AnomaliTransform import AnomaliTransform, EntityTypes

api_base = "https://api.greynoise.io/"
api_key = None
api_type = "enterprise"

VERSION = "3.0.0"
USER_AGENT = "greynoise-anomali-transform-" + VERSION


def searchiptransform(at, search_string):  # noqa: C901
    """
    Transform an IP address by enriching it with GreyNoise intelligence data.

    This function queries the GreyNoise API for information about the specified IP address
    and creates entities in Anomali ThreatStream based on the intelligence gathered. It
    identifies whether the IP is Internet noise, a common business service, associated with
    known actors, or has other relevant security characteristics.

    Args:
        at (AnomaliTransform): The Anomali Transform object used to add entities and exceptions.
        search_string (str): The IP address to search for in GreyNoise.

    Returns:
        AnomaliTransform: The transform object with added entities and/or exceptions.

    Entities Created:
        - Phrase: "Internet Noise" if IP is found as an internet scanner
        - Phrase: "Common Business Service" if IP is a known business service
        - Phrase: "actor: <name>" if associated with a known threat actor
        - Phrase: "business service: <name>" if identified as a business service provider
        - Phrase: "classification: <type>" for the IP's classification (malicious/benign/unknown)
        - AS: ASN number (with "AS" prefix removed) if available
        - Phrase: "Known VPN Service: <name>" if IP is identified as VPN
        - Phrase: "Known Tor Exit Node" if IP is a Tor exit node
        - Phrase: "Not Internet Noise" if IP is not found in GreyNoise (404 response)

    Error Handling:
        - 400: Invalid IP address format
        - 401: API key is missing, expired, or incorrect
        - 404: IP not found in GreyNoise database
        - 429: API rate limit reached
        - 500: GreyNoise API error

    Example:
        >>> at = AnomaliTransform()
        >>> searchiptransform(at, "8.8.8.8")
        # Returns transform object with entities for Google DNS server
    """
    try:
        response = requests.get(
            api_base + "v3/ip/" + search_string,
            headers={
                "Accept": "application/json",
                "key": api_key,
                "User-Agent": USER_AGENT,
            },
        )
        response_json = response.json()

        if response.status_code == 200:
            if response_json.get("internet_scanner_intelligence", {}).get("found"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Internet Noise")
            if response_json.get("business_service_intelligence", {}).get("found"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Common Business Service")
            actor = response_json.get("internet_scanner_intelligence", {}).get("actor", "unknown")
            if actor and actor != "unknown":
                at.addEntity(EntityTypes.Phrase, "%s" % "actor: " + actor)
            bs_provider = response_json.get("business_service_intelligence", {}).get("name", "unknown")
            if bs_provider and bs_provider != "unknown":
                at.addEntity(EntityTypes.Phrase, "%s" % "business service: " + bs_provider)
            if (
                response_json.get("internet_scanner_intelligence", {}).get("classification", "")
                and response_json.get("internet_scanner_intelligence", {}).get("classification", "") != ""
            ):
                at.addEntity(
                    EntityTypes.Phrase,
                    "%s" % "classification: "
                    + response_json.get("internet_scanner_intelligence", {}).get("classification", ""),
                )
            asn_value = response_json.get("internet_scanner_intelligence", {}).get("metadata", {}).get("asn")
            if asn_value.startswith("AS"):
                asn_value = asn_value[2:]
            if asn_value and asn_value != "":
                at.addEntity(EntityTypes.AS, "%s" % asn_value)
            if (
                response_json.get("internet_scanner_intelligence", {}).get("vpn", False)
                and response_json.get("internet_scanner_intelligence", {}).get("vpn", "False") == "True"
            ):
                at.addEntity(
                    EntityTypes.Phrase,
                    "%s" % "Known VPN Service: "
                    + response_json.get("internet_scanner_intelligence", {}).get("vpn_service", "Unidentified"),
                )
            if (
                response_json.get("internet_scanner_intelligence", {}).get("tor", False)
                and response_json.get("internet_scanner_intelligence", {}).get("tor", "False") == "True"
            ):
                at.addEntity(EntityTypes.Phrase, "%s" % "Known Tor Exit Node")
        elif response.status_code == 404:
            at.addEntity(EntityTypes.Phrase, "%s" % "Not Internet Noise")
        elif response.status_code == 400:
            at.addException("Invalid IP Address, please verify")
        elif response.status_code == 401:
            at.addException("API Key is Missing, Expired or Incorrect, please verify")
        elif response.status_code == 429:
            at.addException("API Rate-Limit Reached, Please try again tomorrow.")
        elif response.status_code == 500:
            at.addException("An error occurred with the GreyNoise API, please contact GreyNoise for assistance.")
    except:  # noqa E722
        at.addException(
            "Search IP Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
    return at


functions = {"Search IP": searchiptransform}

if __name__ == "__main__":
    at = AnomaliTransform()
    at.parseArguments()
    transform_name = at.getTransformName()
    entity_value = at.getEntityValue()
    api_key = at.getCredentialValue("api_key")

    functions[transform_name](at, entity_value)
    at.returnOutput()
