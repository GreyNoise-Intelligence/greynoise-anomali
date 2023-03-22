import copy
import datetime
import json
import os
import sys

import requests
from AnomaliEnrichment import (
    AnomaliEnrichment,
    ChartWidget,
    CompositeItem,
    HorizontalRuleWidget,
    ItemInWidget,
    ItemTypes,
    TableWidget,
    TextWidget,
)

api_base = "https://api.greynoise.io/"
api_key = None
api_type = "enterprise"

VERSION = "2.4.0"

xrange_template_dict = {
    "chart": {"type": "xrange", "height": 350},
    "title": {"text": "IP Timeline"},
    "xAxis": {"type": "datetime"},
    "yAxis": {
        "title": {"text": ""},
        "categories": ["Classification", "rDNS", "ASN"],
        "gridLineWidth": 0,
        "reversed": True,
    },
    "tooltip": {"pointFormat": "{point.value}"},
    "series": [
        {"name": "Timeline", "borderColor": "white", "pointWidth": 25, "data": []}
    ],
}


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

            if response.status_code == 200:
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
                        ItemInWidget(itemValue="Is Common Business Service"),
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
                date_object = datetime.datetime.strptime(
                    response_json.get("last_seen"), "%Y-%m-%d"
                ).date()
                last_seen_formatted = date_object.strftime("%-d %b %Y")
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last Seen"),
                        ItemInWidget(itemValue=last_seen_formatted),
                    ]
                )

                anomali_enrichment.addWidget(table_widget)
                # Community Table Widget #1 End

            else:
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
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "IP not seen scanning the Internet by GreyNoise in last 90 Days",
                            "IP not seen scanning the Internet by GreyNoise in last 90 Days",
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
                        "GreyNoise Intel for %s" % search_string,
                        "GreyNoise Intel for %s" % search_string,
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
            date_object = datetime.datetime.strptime(
                response_json.get("last_seen"), "%Y-%m-%d"
            ).date()
            last_seen_formatted = date_object.strftime("%-d %b %Y")
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Last Seen"),
                    ItemInWidget(itemValue=last_seen_formatted),
                ]
            )
            date_object = datetime.datetime.strptime(
                response_json.get("first_seen"), "%Y-%m-%d"
            ).date()
            first_seen_formatted = date_object.strftime("%-d %b %Y")
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="First Seen"),
                    ItemInWidget(itemValue=first_seen_formatted),
                ]
            )
            if response_json["classification"] == "malicious":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Classification"),
                        ItemInWidget(
                            itemValue=str(response_json["classification"]).capitalize(),
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
                            itemValue=str(response_json["classification"]).capitalize(),
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
                            itemValue=str(response_json["classification"]).capitalize(),
                            backgroundColor="Grey",
                            textColor="Black",
                        ),
                    ]
                )
            if response_json.get("actor") and response_json.get("actor") != "unknown":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Actor"),
                        ItemInWidget(
                            itemValue=response_json.get("actor", "Unknown") or "Unknown"
                        ),
                    ]
                )

            anomali_enrichment.addWidget(table_widget)
            # Table Widget #1 End

            # Table Widget #2 Start
            table_widget_metadata = TableWidget(
                "Metadata", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            if (
                response_json["metadata"].get("asn")
                and response_json["metadata"].get("asn") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="ASN"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get("asn", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("city")
                and response_json["metadata"].get("city") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="City"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get("city", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("country")
                and response_json["metadata"].get("country") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Source Country"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get(
                                "country", "Unknown"
                            )
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("country_code")
                and response_json["metadata"].get("country_code") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Source Country Code"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get(
                                "country_code", "Unknown"
                            )
                            or "Unknown"
                        ),
                    ]
                )
            if response_json["metadata"].get("destination_countries"):
                dest_countries = ", ".join(
                    response_json["metadata"]["destination_countries"]
                )
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Destination Countries"),
                        ItemInWidget(itemValue=dest_countries or "Unknown"),
                    ]
                )
            if response_json["metadata"].get("destination_country_codes"):
                dest_country_codes = ", ".join(
                    response_json["metadata"]["destination_country_codes"]
                )
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Destination Country Codes"),
                        ItemInWidget(itemValue=dest_country_codes or "Unknown"),
                    ]
                )
            if (
                response_json["metadata"].get("region")
                and response_json["metadata"].get("region") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Region"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get("region", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("organization")
                and response_json["metadata"].get("organization") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Organization"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get(
                                "organization", "Unknown"
                            )
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("category")
                and response_json["metadata"].get("category") != "unknown"
            ):
                table_widget_metadata.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Category"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get(
                                "category", "Unknown"
                            )
                            or "Unknown"
                        ),
                    ]
                )
            anomali_enrichment.addWidget(table_widget_metadata)
            # Table Widget #2 End

            # Table Widget #3 Start
            table_widget_additional = TableWidget(
                "Additional", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="Known Tor Exit Node"),
                    ItemInWidget(
                        itemValue=str(
                            response_json["metadata"].get("tor", "False")
                        ).capitalize()
                        or "False"
                    ),
                ]
            )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="Spoofable"),
                    ItemInWidget(
                        itemValue=str(
                            response_json.get("spoofable", "False")
                        ).capitalize()
                        or "False"
                    ),
                ]
            )
            if (
                response_json["metadata"].get("rdns")
                and response_json["metadata"].get("rdns") != "unknown"
            ):
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(itemValue="rDNS"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get("rdns", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            if (
                response_json["metadata"].get("os")
                and response_json["metadata"].get("os") != "unknown"
            ):
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(itemValue="OS"),
                        ItemInWidget(
                            itemValue=response_json["metadata"].get("os", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="VPN"),
                    ItemInWidget(
                        itemValue=str(response_json.get("vpn", "False")).capitalize()
                        or "False"
                    ),
                ]
            )
            if response_json.get("vpn"):
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(itemValue="VPN Service"),
                        ItemInWidget(
                            itemValue=response_json.get("vpn_service", "Unknown")
                            or "Unknown"
                        ),
                    ]
                )
            table_widget_additional.addRowOfItems(
                [
                    ItemInWidget(itemValue="Known BOT Activity"),
                    ItemInWidget(
                        itemValue=str(response_json.get("bot", "False")).capitalize()
                        or "False"
                    ),
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(response_json["raw_data"]["scan"]))
                            ),
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(response_json["tags"]))
                            ),
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(response_json["cve"]))
                            ),
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(response_json["raw_data"]["ja3"]))
                            ),
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
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(response_json["raw_data"]["hassh"]))
                            ),
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

        elif (
            response.status_code == 200
            and riot_response.status_code == 200
            and riot_response_json.get("riot")
        ):
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
                        "https://viz.greynoise.io/ip/%s" % search_string,
                        "View on GreyNoise Visualizer",
                    ),
                    True,
                )
            )

            # Table Widget #1 Start
            table_widget = TableWidget(
                "Details", ["Key", "Value"], columnWidths=["20%", "80%"]
            )
            date_object = datetime.datetime.strptime(
                riot_response_json.get("last_updated").split("T")[0], "%Y-%m-%d"
            ).date()
            last_updated_formatted = date_object.strftime("%-d %b %Y")
            table_widget.addRowOfItems(
                [
                    ItemInWidget(itemValue="Last Updated"),
                    ItemInWidget(itemValue=last_updated_formatted),
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
            if riot_response_json["trust_level"] == "1":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Trust Level"),
                        ItemInWidget(
                            itemValue="1 - Reasonably Ignore",
                            backgroundColor="#3CB371",
                            textColor="White",
                        ),
                    ]
                )
            elif riot_response_json["trust_level"] == "2":
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Trust Level"),
                        ItemInWidget(
                            itemValue="2 - Commonly Seen",
                            backgroundColor="#F6BE00",
                            textColor="White",
                        ),
                    ]
                )
            else:
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Trust Level"),
                        ItemInWidget(
                            itemValue=riot_response_json.get("trust_level", "Unknown")
                            or "Unknown"
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
        elif response.status_code == 401:
            anomali_enrichment.addException(
                "API Key is Missing, Expired or Incorrect, please verify"
            )
        elif response.status_code == 429:
            anomali_enrichment.addException(
                "API Rate-Limit Reached, Please try again tomorrow."
            )
        elif response.status_code == 500:
            anomali_enrichment.addException(
                "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
            )
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIP Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
    return anomali_enrichment


def enrichIPSim(anomali_enrichment, search_string):  # noqa: C901
    try:
        if api_type.lower() == "community":
            anomali_enrichment.addException(
                "IP Similarity Not Supported with Community API Key"
            )
        else:
            # builds response if paid api is being used
            similarity_response = requests.get(
                api_base
                + "v3/similarity/ips/"
                + search_string
                + "?limit=50&minimum_score=0.9",
                headers={
                    "Accept": "application/json",
                    "key": api_key,
                    "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
                },
            )
            similarity_response_json = similarity_response.json()

            if (
                similarity_response.status_code == 200
                and similarity_response_json
                and int(similarity_response_json["total"]) > 1
            ):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "GreyNoise Similarity Intel for %s" % search_string,
                            "GreyNoise Similarity Intel for %s" % search_string,
                            "#A9A9A9",
                            "#FFFFFF",
                            "30px",
                            "bold",
                        ),
                        True,
                    )
                )
                if int(similarity_response_json["total"]) > 50:
                    anomali_enrichment.addWidget(
                        TextWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Showing first 50 IPs of {} IPs that have a similarity score "
                                "of 90% or above to {}".format(
                                    similarity_response_json["total"], search_string
                                ),
                            )
                        )
                    )
                else:
                    anomali_enrichment.addWidget(
                        TextWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Showing {} IPs that have a similarity score "
                                "of 90% or above to {}".format(
                                    similarity_response_json["total"], search_string
                                ),
                            )
                        )
                    )
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.Link,
                            "https://viz.greynoise.io/ip-similarity/%s" % search_string,
                            "View IP Similarity UI on GreyNoise Visualizer",
                        ),
                        True,
                    )
                )
                # Table Widget #4 Start
                table_widget_similarity = TableWidget(
                    "Similar IPs",
                    [
                        "IP",
                        "Score",
                        "Classification",
                        "Actor",
                        "Last Seen",
                        "Organization",
                        "Features Matched",
                    ],
                    columnWidths=["10%", "5%", "10%", "15%", "10%", "15%", "35%"],
                )
                for similar_ip in similarity_response_json["similar_ips"]:
                    features = ", ".join(similar_ip.get("features"))
                    similar_ip["score"] = str(int(similar_ip.get("score") * 100)) + "%"
                    date_object = datetime.datetime.strptime(
                        similar_ip.get("last_seen"), "%Y-%m-%d"
                    ).date()
                    last_seen_formatted = date_object.strftime("%-d %b %Y")
                    table_widget_similarity.addRowOfItems(
                        [
                            ItemInWidget(
                                ItemTypes.Link,
                                "/detail/v2/ip?value={}".format(similar_ip.get("ip")),
                                similar_ip.get("ip"),
                            ),
                            ItemInWidget(itemValue=similar_ip.get("score")),
                            ItemInWidget(itemValue=similar_ip.get("classification")),
                            ItemInWidget(itemValue=similar_ip.get("actor")),
                            ItemInWidget(itemValue=last_seen_formatted),
                            ItemInWidget(itemValue=similar_ip.get("organization")),
                            ItemInWidget(itemValue=features),
                        ]
                    )
                anomali_enrichment.addWidget(table_widget_similarity)
                # Table Widget #4 End
            elif similarity_response.status_code == 403:
                horizontal_rule_widget = HorizontalRuleWidget()
                anomali_enrichment.addWidget(horizontal_rule_widget)
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "GreyNoise Similarity Intel for %s is not available with your Subscription"
                            % search_string,
                            "GreyNoise Similarity Intel for %s is not available with your Subscription"
                            % search_string,
                            "#A9A9A9",
                            "#FFFFFF",
                            "30px",
                            "bold",
                        ),
                        True,
                    )
                )
            elif similarity_response.status_code == 401:
                anomali_enrichment.addException(
                    "API Key is Missing, Expired or Incorrect, please verify"
                )
            elif similarity_response.status_code == 429:
                anomali_enrichment.addException(
                    "API Rate-Limit Reached, Please try again tomorrow."
                )
            elif similarity_response.status_code == 500:
                anomali_enrichment.addException(
                    "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
                )
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIPSimilar Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )

    return anomali_enrichment


def enrichIPTimeline(anomali_enrichment, search_string):  # noqa: C901
    try:
        if api_type.lower() == "community":
            anomali_enrichment.addException(
                "IP Timeline Not Supported with Community API Key"
            )
        else:
            # builds response if paid api is being used
            timeline_response = requests.get(
                api_base
                + "v3/noise/ips/"
                + search_string
                + "/daily-summary?days=30&limit=50",
                headers={
                    "Accept": "application/json",
                    "key": api_key,
                    "User-Agent": "greynoise-anomali-enrichment-" + VERSION,
                },
            )
            timeline_response_json = timeline_response.json()

            if (
                timeline_response.status_code == 200
                and timeline_response_json
                and timeline_response_json["activity"]
            ):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "GreyNoise Timeline Details for %s" % search_string,
                            "GreyNoise Timeline Details for %s" % search_string,
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
                            "Showing Daily Summary of events for last 30 days.  Only days with events will display.",
                        )
                    )
                )
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.Link,
                            "https://viz.greynoise.io/ip/%s?view=timeline"
                            % search_string,
                            "View IP Timeline Details on GreyNoise Visualizer",
                        ),
                        True,
                    )
                )
                # Table Widget #5 Start
                table_widget_timeline = TableWidget(
                    "IP Timeline",
                    [
                        "Date",
                        "Classification",
                        "Tags",
                        "rDNS",
                        "Organization",
                        "ASN",
                        "Ports",
                        "Web Paths",
                        "User Agents",
                    ],
                )
                xrange_data = []
                asn_dict = {}
                rdns_dict = {}
                colors = ["gray", "blue", "purple", "orange", "black"]
                for activity in reversed(timeline_response_json.get("activity")):
                    tags = []
                    for tag in activity["tags"]:
                        tags.append(tag["name"])
                    tags_string = ", ".join(tags)
                    ports = []
                    for item in activity["protocols"]:
                        ports.append(
                            str(item["port"]) + "/" + str(item["transport_protocol"])
                        )
                    ports_string = ", ".join(ports)
                    paths = ", ".join(activity["http_paths"])
                    user_agents = "| ".join(activity["http_user_agents"])
                    date = activity["timestamp"].split("T")[0]
                    date_object = datetime.datetime.strptime(date, "%Y-%m-%d").date()
                    date_formatted = date_object.strftime("%-d %b %Y")
                    table_widget_timeline.addRowOfItems(
                        [
                            ItemInWidget(itemValue=date_formatted),
                            ItemInWidget(itemValue=activity["classification"]),
                            ItemInWidget(itemValue=tags_string),
                            ItemInWidget(itemValue=activity["rdns"]),
                            ItemInWidget(itemValue=activity["organization"]),
                            ItemInWidget(itemValue=activity["asn"]),
                            ItemInWidget(itemValue=ports_string),
                            ItemInWidget(itemValue=paths),
                            ItemInWidget(itemValue=user_agents),
                        ]
                    )
                    start_date = datetime.datetime.strptime(date, "%Y-%m-%d")
                    end_date = start_date + datetime.timedelta(days=1)
                    start_date = int(start_date.timestamp()) * 1000
                    end_date = int(end_date.timestamp()) * 1000
                    if activity["classification"]:
                        if activity["classification"] == "benign":
                            color = "green"
                        elif activity["classification"] == "malicious":
                            color = "red"
                        else:
                            color = "gray"
                        classification_data = {
                            "x": start_date,
                            "x2": end_date,
                            "y": 0,
                            "color": color,
                            "value": "Classification: " + activity["classification"],
                        }
                        xrange_data.append(classification_data)
                    if activity["rdns"]:
                        if activity["rdns"] not in rdns_dict.keys():
                            rdns_dict[activity["rdns"]] = colors[len(rdns_dict)]
                        rdns_data = {
                            "x": start_date,
                            "x2": end_date,
                            "y": 1,
                            "color": rdns_dict[activity["rdns"]],
                            "value": "rDNS: " + activity["rdns"],
                        }
                        xrange_data.append(rdns_data)
                    if activity["asn"]:
                        if activity["asn"] not in asn_dict.keys():
                            asn_dict[activity["asn"]] = colors[len(asn_dict)]
                        asn_data = {
                            "x": start_date,
                            "x2": end_date,
                            "y": 2,
                            "color": asn_dict[activity["asn"]],
                            "value": "ASN: " + activity["asn"],
                        }
                        xrange_data.append(asn_data)
                anomali_enrichment.addWidget(table_widget_timeline)

                # Table Widget #5 End

                # Create XRange ChartWidget
                def create_chart_widget(template_dict, data):
                    graph_dict = copy.deepcopy(template_dict)
                    # fill in the data
                    graph_dict["series"][0]["data"] = data
                    graph_json = json.dumps(graph_dict)
                    xrange_chart_widget = ChartWidget("IP Timeline", graph_json)
                    return xrange_chart_widget

                chart_widget = create_chart_widget(xrange_template_dict, xrange_data)
                anomali_enrichment.addWidget(chart_widget)
            elif timeline_response.status_code == 403:
                horizontal_rule_widget = HorizontalRuleWidget()
                anomali_enrichment.addWidget(horizontal_rule_widget)
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "GreyNoise Timeline Details for %s are not available with your Subscription"
                            % search_string,
                            "GreyNoise Timeline Details for %s are not available with your Subscription"
                            % search_string,
                            "#A9A9A9",
                            "#FFFFFF",
                            "30px",
                            "bold",
                        ),
                        True,
                    )
                )
            elif timeline_response.status_code == 401:
                anomali_enrichment.addException(
                    "API Key is Missing, Expired or Incorrect, please verify"
                )
            elif timeline_response.status_code == 429:
                anomali_enrichment.addException(
                    "API Rate-Limit Reached, Please try again tomorrow."
                )
            elif timeline_response.status_code == 500:
                anomali_enrichment.addException(
                    "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
                )
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIPTimeline Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )

    return anomali_enrichment


functions = {
    "enrichIP": enrichIP,
    "enrichIPSim": enrichIPSim,
    "enrichIPTimeline": enrichIPTimeline,
}

if __name__ == "__main__":
    anomali_enrichment = AnomaliEnrichment()
    anomali_enrichment.parseArguments()
    transform_name = anomali_enrichment.getTransformName()
    entity_value = anomali_enrichment.getEntityValue()
    api_key = anomali_enrichment.getCredentialValue("api_key")
    api_type = anomali_enrichment.getCredentialValue("api_type")
    if not api_type or api_type == "":
        api_type = "enterprise"

    functions[transform_name](anomali_enrichment, entity_value)
    anomali_enrichment.returnOutput()
