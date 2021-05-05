import os
import sys
import requests

from AnomaliTransform import AnomaliTransform
from AnomaliTransform import EntityTypes

api_base = "https://api.greynoise.io/v2"
api_key = None

VERSION = "2.0.0"


def enrichiptransform(at, search_string):
    try:
        response = requests.get(
            api_base + "/noise/context/" + search_string,
            headers={
                "Accept": "application/json",
                "key": api_key,
                "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
            },
        )
        response_json = response.json()

        if response.status_code == 401:
            anomali_enrichment.addException(
                "API Key is Missing, Expired or Incorrect, please verify"
            )

        riot_response = requests.get(
            api_base + "/riot/" + search_string,
            headers={
                "Accept": "application/json",
                "key": api_key,
                "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
            },
        )
        riot_response_json = riot_response.json()

        if response.status_code == 200 and response_json["seen"]:
            at.addEntity(EntityTypes.Phrase, "%s" % "Internet Noise")
            at.addEntity(EntityTypes.Phrase, "%s" % "GN Classification: " + response_json["classification"])
            at.addEntity(EntityTypes.AS, "%s" % response_json["metadata"]["asn"])
            if response_json["vpn"]:
                at.addEntity(
                    EntityTypes.Phrase,
                    "%s" % "Known VPN Service: " + response_json["vpn_service"],
                )
            if response_json["bot"]:
                at.addEntity(EntityTypes.Phrase, "%s" % "Known Bot Activity")
            if response_json["metadata"]["tor"]:
                at.addEntity(EntityTypes.Phrase, "%s" % "Known Tor Exit Node")
            if response_json["classification"] == "benign":
                at.addEntity(EntityTypes.Phrase, "%s" % response_json["actor"])
        if riot_response.status_code == 200 and riot_response_json["riot"]:
            at.addEntity(EntityTypes.Phrase, "%s" % "Benign Service")
            at.addEntity(EntityTypes.Phrase, "%s" % riot_response_json["name"])
        if (
            response.status_code == 200
            and not riot_response_json["riot"]
            and not response_json["seen"]
        ):
            at.addEntity(EntityTypes.Phrase, "%s" % "Not Internet Noise")
    except:
        at.addException(
            "enrichIP Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
    return at


functions = {"Search IP": enrichiptransform}


if __name__ == "__main__":
    at = AnomaliTransform()
    at.parseArguments()
    transform_name = at.getTransformName()
    entity_value = at.getEntityValue()
    api_key = at.getCredentialValue("api_key")

    functions[transform_name](at, entity_value)
    at.returnOutput()
