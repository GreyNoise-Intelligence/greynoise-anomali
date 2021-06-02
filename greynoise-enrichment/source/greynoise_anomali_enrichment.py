import os
import sys

import requests

from AnomaliEnrichment import (
    AnomaliEnrichment,
    TextWidget,
    TableWidget,
    ItemInWidget,
    ItemTypes,
    CompositeItem,
)

api_base = "https://api.greynoise.io/"
api_key = None
api_type = "enterprise"

VERSION = "2.1.0"


def enrichIP(anomali_enrichment, search_string):  # noqa: C901
    try:
        # builds response if community api is being used
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

            if response.status_code == 401:
                anomali_enrichment.addException(
                    "API Key is Missing, Expired or Incorrect, please verify"
                )
        else:
            # builds response if paid api is being used
            response = requests.get(
                api_base + "v2/noise/context/" + search_string,
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
            # builds riot response
            riot_response = requests.get(
                api_base + "v2/riot/" + search_string,
                headers={
                    "Accept": "application/json",
                    "key": api_key,
                    "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
                },
            )
            riot_response_json = riot_response.json()

        # looks for success and community offering
        if (
            response.status_code == 200 or response.status_code == 404
        ) and api_type.lower() == "community":
            if response_json.get("noise") or response_json.get("riot"):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "GreyNoise Community Info for %s" % search_string,
                            "GreyNoise Community Info for %s" % search_string,
                            "#A9A9A9",
                            "#FFFFFF",
                            "30px",
                            "bold",
                        ),
                        True,
                    )
                )
                if response_json.get("noise"):
                    anomali_enrichment.addWidget(
                        TextWidget(
                            ItemInWidget(
                                ItemTypes.Link,
                                "https://viz.greynoise.io/ip/%s" % search_string,
                                "View on GreyNoise Visualizer",
                            ),
                            True,
                        )
                    )
                elif response_json.get("riot") and not response_json.get("noise"):
                    anomali_enrichment.addWidget(
                        TextWidget(
                            ItemInWidget(
                                ItemTypes.Link,
                                "https://viz.greynoise.io/riot/%s" % search_string,
                                "View on GreyNoise Visualizer",
                            ),
                            True,
                        )
                    )
                if response_json.get("noise") and response_json.get("riot"):
                    anomali_enrichment.addWidget(
                        TextWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "%s was also found in GreyNoise RIOT "
                                "Dataset" % search_string,
                                "%s was also found in GreyNoise RIOT "
                                "Dataset" % search_string,
                                "#3CB371",
                                "#FFFFFF",
                                "20px",
                                "bold",
                            ),
                            True,
                        )
                    )

                # Community Table Widget #1 Start
                table_widget = TableWidget(
                    "Details", ["Key", "Value"], columnWidths=["20%", "80%"]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Is Internet Background Noise"),
                        ItemInWidget(itemValue=response_json.get("noise")),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Is Benign Service"),
                        ItemInWidget(itemValue=response_json.get("riot")),
                    ]
                )
                if response_json.get("classification") == "malicious":
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=response_json.get("classification"),
                                backgroundColor="Red",
                                textColor="White",
                            ),
                        ]
                    )
                elif response_json.get("classification") == "benign":
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=response_json.get("classification"),
                                backgroundColor="#3CB371",
                                textColor="White",
                            ),
                        ]
                    )
                else:
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=response_json.get("classification"),
                                backgroundColor="Grey",
                                textColor="Black",
                            ),
                        ]
                    )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Actor or Provider"),
                        ItemInWidget(itemValue=response_json.get("name")),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last Seen"),
                        ItemInWidget(itemValue=response_json.get("last_seen")),
                    ]
                )

                anomali_enrichment.addWidget(table_widget)
                # Community Table Widget #1 End

            else:
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "IP not seen scanning the Internet by "
                            "GreyNoise in last 90 Days",
                            "IP not seen scanning the Internet by "
                            "GreyNoise in last 90 Days",
                            "#FFFFFF",
                            "#000000",
                            "15px",
                        ),
                        True,
                    )
                )
        # looks for success and paid offering
        elif response.status_code == 200 and response_json.get("seen"):
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise Info for %s" % search_string,
                        "GreyNoise Info for %s" % search_string,
                        "#A9A9A9",
                        "#FFFFFF",
                        "30px",
                        "bold",
                    ),
                    True,
                )
            )
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.Link,
                        "https://viz.greynoise.io/ip/%s" % search_string,
                        "View on GreyNoise Visualizer",
                    ),
                    True,
                )
            )
            if riot_response_json.get("riot"):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "%s was also found in GreyNoise RIOT Dataset"
                            % search_string,
                            "%s was also found in GreyNoise RIOT Dataset"
                            % search_string,
                            "#3CB371",
                            "#FFFFFF",
                            "20px",
                            "bold",
                        ),
                        True,
                    )
                )

            # Table Widget #1 Start
            table_widget = TableWidget(
                "Details", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Last Seen"),
                    ItemInWidget(itemValue=response_json["last_seen"]),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="First Seen"),
                    ItemInWidget(itemValue=response_json["first_seen"]),
                ]
            )
            if response_json["classification"] == "malicious":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Classification"),
                        ItemInWidget(
                            itemValue=response_json["classification"],
                            backgroundColor="Red",
                            textColor="White",
                        ),
                    ]
                )
            elif response_json["classification"] == "benign":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Classification"),
                        ItemInWidget(
                            itemValue=response_json["classification"],
                            backgroundColor="#3CB371",
                            textColor="White",
                        ),
                    ]
                )
            else:
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Classification"),
                        ItemInWidget(
                            itemValue=response_json["classification"],
                            backgroundColor="Grey",
                            textColor="Black",
                        ),
                    ]
                )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Actor"),
                    ItemInWidget(
                        itemValue=response_json.get("actor", "unknown") or "unknown"
                    ),
                ]
            )

            anomali_enrichment.addWidget(table_widget)
            # Table Widget #1 End

            # Table Widget #2 Start
            table_widget_metadata = TableWidget(
                "Metadata", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="ASN"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("asn", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="City"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("city", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="Country"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("country", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="Country Code"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get(
                            "country_code", "unknown"
                        )
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="Region"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("region", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="Organization"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get(
                            "organization", "unknown"
                        )
                        or "unknown"
                    ),
                ]
            )
            table_widget_metadata.addRowOfItems(
                [
                    ItemInWidget(itemValue="Category"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("category", "unknown")
                        or "unknown"
                    ),
                ]
            )
            anomali_enrichment.addWidget(table_widget_metadata)
            # Table Widget #1 End

            # Table Widget #3 Start
            table_widget_additional = TableWidget(
                "Additional", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="Tor"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("tor", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="Spoofable"),
                    ItemInWidget(
                        itemValue=response_json.get("spoofable", "false") or "false"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="rDNS"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("rdns", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="OS"),
                    ItemInWidget(
                        itemValue=response_json["metadata"].get("os", "unknown")
                        or "unknown"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="VPN"),
                    ItemInWidget(
                        itemValue=response_json.get("vpn", "false") or "false"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="VPN Service"),
                    ItemInWidget(
                        itemValue=response_json.get("vpn_service", "N/A") or "N/A"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="BOT"),
                    ItemInWidget(itemValue=response_json.get("bot", "N/A") or "N/A"),
                ]
            )

            # Create composite_item for TextWidget
            # always declare a new CompositeItem before using it
            port_composite_item = CompositeItem(onSeparateLines=False)
            port_list = []
            if response_json["raw_data"]["scan"]:
                for item in response_json["raw_data"]["scan"][:10]:
                    port_list.append(str(item["port"]) + "/" + str(item["protocol"]))
            if port_list:
                for port in port_list:
                    port_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, port)
                    )

                if len(response_json["raw_data"]["scan"]) > 10:
                    port_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} "
                                "items, see Visualizer for more details."
                            ).format(str(len(response_json["raw_data"]["scan"]))),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "Port(s) / Protocol(s)"),
                        port_composite_item,
                    ]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "Port(s) / Protocol(s)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            tag_composite_item = CompositeItem(onSeparateLines=False)
            tag_list = []
            if response_json["tags"]:
                tag_list = response_json["tags"][:10]
            if tag_list:
                for tag in tag_list:
                    tag_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, str(tag))
                    )
                if len(response_json["tags"]) > 10:
                    tag_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} items,"
                                " see Visualizer for more details."
                            ).format(str(len(response_json["tags"]))),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, "Tag(s)"), tag_composite_item]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "Tag(s)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            cve_composite_item = CompositeItem(onSeparateLines=False)
            cve_list = []
            if response_json["cve"]:
                cve_list = response_json["cve"][:10]
            if cve_list:
                for cve in cve_list:
                    cve_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, str(cve))
                    )
                if len(response_json["cve"]) > 10:
                    cve_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} items,"
                                " see Visualizer for more details."
                            ).format(str(len(response_json["cve"]))),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, "CVE(s)"), cve_composite_item]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "CVE(s)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            ua_composite_item = CompositeItem(onSeparateLines=False)
            ua_list = []
            if "useragents" in response_json["raw_data"]["web"]:
                ua_list = response_json["raw_data"]["web"]["useragents"][:10]

            if ua_list:
                for ua in ua_list:
                    ua_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, str(ua))
                    )
                if len(response_json["raw_data"]["web"]["useragents"]) > 10:
                    ua_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} items, "
                                "see Visualizer for more details."
                            ).format(
                                str(len(response_json["raw_data"]["web"]["useragents"]))
                            ),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "UserAgent String(s)"),
                        ua_composite_item,
                    ]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "UserAgent String(s)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            path_composite_item = CompositeItem(onSeparateLines=False)
            paths_list = []
            if "paths" in response_json["raw_data"]["web"]:
                paths_list = response_json["raw_data"]["web"]["paths"][:10]
            if paths_list:
                for path in paths_list:
                    path_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, str(path))
                    )
                if len(response_json["raw_data"]["web"]["paths"]) > 10:
                    path_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} "
                                "items, see Visualizer for more details."
                            ).format(
                                str(len(response_json["raw_data"]["web"]["paths"]))
                            ),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, "Path(s)"), path_composite_item]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "Path(s)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            ja3_composite_item = CompositeItem(onSeparateLines=False)
            ja3_list = []
            if "ja3" in response_json["raw_data"]:
                for item in response_json["raw_data"]["ja3"][:10]:
                    ja3_list.append(
                        str(item["fingerprint"]) + " / " + str(item["port"])
                    )

            if ja3_list:
                for ja3 in ja3_list:
                    ja3_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, ja3)
                    )
                if len(response_json["raw_data"]["ja3"]) > 10:
                    ja3_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} "
                                "items, see Visualizer for more details."
                            ).format(str(len(response_json["raw_data"]["ja3"]))),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "JA3(s) (fingerprint/port)"),
                        ja3_composite_item,
                    ]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "JA3(s) (fingerprint/port)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            hassh_composite_item = CompositeItem(onSeparateLines=False)
            hassh_list = []
            if "hassh" in response_json["raw_data"]:
                for item in response_json["raw_data"]["hassh"][:10]:
                    hassh_list.append(
                        str(item["fingerprint"]) + " / " + str(item["port"])
                    )

            if hassh_list:
                for hassh in hassh_list:
                    hassh_composite_item.addItemInWidget(
                        ItemInWidget(ItemTypes.String, hassh)
                    )
                if len(response_json["raw_data"]["hassh"]) > 10:
                    hassh_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            (
                                "Output limited to 10 of {} "
                                "items, see Visualizer for more details."
                            ).format(str(len(response_json["raw_data"]["hassh"]))),
                        )
                    )

                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "HASSH(s) (fingerprint/port)"),
                        hassh_composite_item,
                    ]
                )
            else:
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(ItemTypes.String, "HASSH(s) (fingerprint/port)"),
                        ItemInWidget(ItemTypes.String, "None"),
                    ]
                )

            anomali_enrichment.addWidget(table_widget_additional)
            # Table Widget #3 End

        elif riot_response.status_code == 200 and riot_response_json["riot"]:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise RIOT Info for %s" % search_string,
                        "GreyNoise RIOT Info for %s" % search_string,
                        "#A9A9A9",
                        "#FFFFFF",
                        "30px",
                        "bold",
                    ),
                    True,
                )
            )
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.Link,
                        "https://viz.greynoise.io/riot/%s" % search_string,
                        "View on GreyNoise Visualizer",
                    ),
                    True,
                )
            )

            # Table Widget #1 Start
            table_widget = TableWidget(
                "Details", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Last Updated"),
                    ItemInWidget(itemValue=riot_response_json["last_updated"]),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Category"),
                    ItemInWidget(itemValue=riot_response_json["category"]),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Name"),
                    ItemInWidget(
                        itemValue=riot_response_json.get("name", "unknown") or "unknown"
                    ),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Classification"),
                    ItemInWidget(
                        itemValue="Benign Service",
                        backgroundColor="#3CB371",
                        textColor="White",
                    ),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Description"),
                    ItemInWidget(itemValue=riot_response_json["description"]),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Explanation"),
                    ItemInWidget(itemValue=riot_response_json["explanation"]),
                ]
            )
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Reference URL"),
                    ItemInWidget(itemValue=riot_response_json["reference"]),
                ]
            )
            anomali_enrichment.addWidget(table_widget)
            # Table Widget #1 End
        elif response.status_code == 200 and not response_json["seen"]:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise Info for %s" % search_string,
                        "GreyNoise Info for %s" % search_string,
                        "#A9A9A9",
                        "#FFFFFF",
                        "30px",
                        "bold",
                    ),
                    True,
                )
            )
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "IP not seen scanning the Internet by GreyNoise"
                        " in last 90 Days",
                        "IP not seen scanning the Internet by GreyNoise"
                        " in last 90 Days",
                        "#FFFFFF",
                        "#000000",
                        "15px",
                    ),
                    True,
                )
            )

        else:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "API Returned Status Code: %s.  Check your API Key "
                        "and connection to resolve or contact GreyNoise for "
                        "assistance." % response.status_code,
                        "API Returned Status Code: %s.  Check your API Key "
                        "and connection to resolve or contact GreyNoise for "
                        "assistance." % response.status_code,
                        "#A9A9A9",
                        "#FFFFFF",
                        "10px",
                    ),
                    True,
                )
            )
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIP Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
    return anomali_enrichment


functions = {"enrichIP": enrichIP}

if __name__ == "__main__":
    anomali_enrichment = AnomaliEnrichment()
    anomali_enrichment.parseArguments()
    transform_name = anomali_enrichment.getTransformName()
    entity_value = anomali_enrichment.getEntityValue()
    api_key = anomali_enrichment.getCredentialValue("api_key")
    api_type = anomali_enrichment.getCredentialValue("api_type")

    functions[transform_name](anomali_enrichment, entity_value)
    anomali_enrichment.returnOutput()
