import os
import sys

import requests
from AnomaliTransform import AnomaliTransform, EntityTypes

api_base = "https://api.greynoise.io/"
api_key = None
api_type = "enterprise"

VERSION = "2.4.0"


def searchiptransform(at, search_string):  # noqa: C901
    try:
        if api_type.lower() == "community":
            response = requests.get(
                api_base + "v3/community/" + search_string,
                headers={
                    "Accept": "application/json",
                    "key": api_key,
                    "User-Agent": "greynoise-community-anomali-enrichment-" + VERSION,
                },
            )
            response_json = response.json()

        else:
            response = requests.get(
                api_base + "v2/noise/context/" + search_string,
                headers={
                    "Accept": "application/json",
                    "key": api_key,
                    "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
                },
            )
            response_json = response.json()

            if response.status_code == 200:
                riot_response = requests.get(
                    api_base + "v2/riot/" + search_string,
                    headers={
                        "Accept": "application/json",
                        "key": api_key,
                        "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
                    },
                )
                riot_response_json = riot_response.json()

        if (response.status_code == 200 or response.status_code == 404) and api_type.lower() == "community":
            if response_json.get("noise"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Internet Noise")
            if response_json.get("riot"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Common Business Service")
            if response_json.get("name") and response_json.get("name") != "unknown":
                at.addEntity(EntityTypes.Phrase, "%s" % response_json.get("name"))
            if response_json.get("classification"):
                at.addEntity(
                    EntityTypes.Phrase,
                    "%s" % "GN Classification: " + response_json.get("classification", ""),
                )
            if not response_json.get("noise") and not response_json.get("riot"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Not Internet Noise")
        elif response.status_code == 200 and (response_json.get("seen") or riot_response_json.get("riot")):
            if response_json.get("seen"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Internet Noise")
                if response_json.get("classification"):
                    at.addEntity(
                        EntityTypes.Phrase,
                        "%s" % "GN Classification: " + response_json.get("classification", ""),
                    )
                if response_json["metadata"].get("asn"):
                    at.addEntity(EntityTypes.AS, "%s" % response_json["metadata"].get("asn"))
                if response_json.get("vpn") and response_json.get("vpn_service"):
                    at.addEntity(
                        EntityTypes.Phrase,
                        "%s" % "Known VPN Service: " + response_json.get("vpn_service"),
                    )
                if response_json.get("bot"):
                    at.addEntity(EntityTypes.Phrase, "%s" % "Known Bot Activity")
                if response_json["metadata"].get("tor"):
                    at.addEntity(EntityTypes.Phrase, "%s" % "Known Tor Exit Node")
                if response_json.get("classification") == "benign" and response_json.get("actor"):
                    at.addEntity(EntityTypes.Phrase, "%s" % response_json.get("actor"))
            if riot_response_json.get("riot"):
                at.addEntity(EntityTypes.Phrase, "%s" % "Common Business Service")
                at.addEntity(EntityTypes.Phrase, "%s" % riot_response_json.get("name"))
        elif response.status_code == 200 and not riot_response_json.get("riot") and not response_json.get("seen"):
            at.addEntity(EntityTypes.Phrase, "%s" % "Not Internet Noise")
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
    api_type = at.getCredentialValue("api_type")
    if not api_type or api_type == "":
        api_type = "enterprise"

    functions[transform_name](at, entity_value)
    at.returnOutput()
