"""
GreyNoise Anomali ThreatStream Enrichment Plugin.

This module provides enrichment functions for IP addresses within Anomali ThreatStream using
GreyNoise intelligence data. It queries the GreyNoise API and displays comprehensive
intelligence about IP addresses, including internet scanner details, business service
information, metadata, and timeline data.

The plugin supports two main enrichment functions:
    - enrichIP: Provides detailed intelligence about an IP address
    - enrichIPTimeline: Displays historical timeline data for an IP address

Version: 3.0.0
Author: GreyNoise Intelligence
License: See LICENSE.md
"""

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

# Import the new timeline function
try:
    from greynoise_timeline import get_greynoise_timeline
except ImportError:
    # Fallback if import fails
    get_greynoise_timeline = None

api_base = "https://api.greynoise.io/"
api_key = None

VERSION = "3.0.0"
USER_AGENT = "greynoise-anomali-enrichment-" + VERSION

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
    "series": [{"name": "Timeline", "borderColor": "white", "pointWidth": 25, "data": []}],
}


def enrichIP(anomali_enrichment, search_string):  # noqa: C901
    """
    Enrich an IP address with comprehensive GreyNoise intelligence data.

    This function queries the GreyNoise API for detailed information about the specified IP
    address and creates visual widgets in Anomali ThreatStream to display the intelligence.
    It provides data about internet scanner activity, business services, metadata, and various
    technical indicators.

    Args:
        anomali_enrichment (AnomaliEnrichment): The Anomali enrichment object to add widgets to.
        search_string (str): The IP address to enrich.

    Returns:
        AnomaliEnrichment: The enrichment object with added widgets and data.

    Widgets Created (when data available):
        - Header: GreyNoise Intel for {IP} with scanner/business service indicators
        - Link: View on GreyNoise Visualizer
        - Table: Internet Scanner Details (last seen, first seen, classification, actor)
        - Table: Business Service Details (name, category, trust level, description)
        - Table: Metadata (ASN, location, countries, region, sensor data, organization)
        - Table: Additional Info (Tor, spoofable, rDNS, OS, VPN, ports, tags, CVEs,
                 user agents, paths, JA4, JA3, HASSH)

    Error Responses Handled:
        - 400: Invalid IPv4 address format (must be public IPv4)
        - 401: API key missing/expired/incorrect
        - 403: Insufficient API permissions
        - 404: IP not observed by GreyNoise
        - 429: Daily rate limit reached
        - 500: GreyNoise API error
        - Other: Unexpected status codes

    Data Displayed:
        Internet Scanner Intelligence:
            - Last seen timestamp, first seen date
            - Classification (malicious/benign/suspicious/unknown) with color coding
            - Associated threat actor
            - Geographic and network metadata
            - Technical indicators (ports, protocols, tags, CVEs)
            - Fingerprints (JA3, JA4, HASSH)
            - HTTP data (user agents, paths)

        Business Service Intelligence:
            - Service name and category
            - Trust level (1-Reasonably Ignore, 2-Commonly Seen)
            - Last updated date
            - Description and explanation
            - Reference URL

    Example:
        >>> enrichment = AnomaliEnrichment()
        >>> enrichIP(enrichment, "8.8.8.8")
        # Returns enrichment object with Google DNS intelligence
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
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise Intel for %s" % search_string,
                        "GreyNoise Intel for %s" % search_string,
                        "#A9A9A9",
                        "#FFFFFF",
                        "35px",
                        "bold",
                    ),
                    True,
                )
            )
            if response_json.get("internet_scanner_intelligence", {}).get("found"):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "%s is a observed Internet Scanner IP" % search_string,
                            "%s is a observed Internet Scanner IP" % search_string,
                            "##F2A007",
                            "#FFFFFF",
                            "15px",
                        ),
                        True,
                    )
                )
            if response_json.get("business_service_intelligence", {}).get("found"):
                anomali_enrichment.addWidget(
                    TextWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "%s is a observed Business Service IP" % search_string,
                            "%s is a observed Business Service IP" % search_string,
                            "#0096FF",
                            "#FFFFFF",
                            "15px",
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
            if response_json.get("internet_scanner_intelligence", {}).get("found"):
                table_widget = TableWidget("Internet Scanner Details", ["Key", "Value"], columnWidths=["20%", "80%"])
                last_seen_timestamp = response_json.get("internet_scanner_intelligence", {}).get(
                    "last_seen_timestamp", "0000-00-00 00:00:00"
                )
                date_object = datetime.datetime.strptime(last_seen_timestamp, "%Y-%m-%d %H:%M:%S").date()
                last_seen_formatted = date_object.strftime("%-d %b %Y")
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last Seen"),
                        ItemInWidget(itemValue=last_seen_formatted),
                    ]
                )
                if (
                    response_json.get("internet_scanner_intelligence", {}).get("first_seen")
                    and response_json.get("internet_scanner_intelligence", {}).get("first_seen") != ""
                ):
                    first_seen = response_json.get("internet_scanner_intelligence", {}).get("first_seen", "0000-00-00")
                    date_object = datetime.datetime.strptime(first_seen, "%Y-%m-%d").date()
                    first_seen_formatted = date_object.strftime("%-d %b %Y")
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="First Seen"),
                            ItemInWidget(itemValue=first_seen_formatted),
                        ]
                    )
                classification = response_json.get("internet_scanner_intelligence", {}).get("classification", "unknown")
                if classification == "malicious":
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=str(classification).capitalize(),
                                backgroundColor="Red",
                                textColor="White",
                            ),
                        ]
                    )
                elif classification == "benign":
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=str(classification).capitalize(),
                                backgroundColor="#3CB371",
                                textColor="White",
                            ),
                        ]
                    )
                elif classification == "suspicious":
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=str(classification).capitalize(),
                                backgroundColor="#FFD700",
                                textColor="White",
                            ),
                        ]
                    )
                else:
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Classification"),
                            ItemInWidget(
                                itemValue=str(classification).capitalize(),
                                backgroundColor="Grey",
                                textColor="Black",
                            ),
                        ]
                    )
                if (
                    response_json.get("internet_scanner_intelligence", {}).get("actor", "unknown")
                    and response_json.get("internet_scanner_intelligence", {}).get("actor", "unknown") != "unknown"
                ):
                    table_widget.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Actor"),
                            ItemInWidget(
                                itemValue=response_json.get("internet_scanner_intelligence", {}).get("actor", "Unknown")
                                or "Unknown"
                            ),
                        ]
                    )

                anomali_enrichment.addWidget(table_widget)
                # Table Widget Internet Scanner Details End

            # Table Widget Business Service Details Start
            if response_json.get("business_service_intelligence", {}).get("found"):
                table_widget = TableWidget("Business Service Details", ["Key", "Value"], columnWidths=["20%", "80%"])
                date_object = datetime.datetime.strptime(
                    response_json.get("business_service_intelligence", {})
                    .get("last_updated", "0000-00-00T00:00:00Z")
                    .split("T")[0],
                    "%Y-%m-%d",
                ).date()
                last_updated_formatted = date_object.strftime("%-d %b %Y")
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Name"),
                        ItemInWidget(
                            itemValue=response_json.get("business_service_intelligence", {}).get("name", "unknown")
                            or "unknown"
                        ),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Category"),
                        ItemInWidget(itemValue=response_json.get("business_service_intelligence", {})["category"]),
                    ]
                )

                if response_json.get("business_service_intelligence", {})["trust_level"] == "1":
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
                elif response_json.get("business_service_intelligence", {})["trust_level"] == "2":
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
                                itemValue=response_json.get("business_service_intelligence", {}).get(
                                    "trust_level", "Unknown"
                                )
                                or "Unknown"
                            ),
                        ]
                    )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last Updated"),
                        ItemInWidget(itemValue=last_updated_formatted),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Description"),
                        ItemInWidget(itemValue=response_json.get("business_service_intelligence", {})["description"]),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Explanation"),
                        ItemInWidget(itemValue=response_json.get("business_service_intelligence", {})["explanation"]),
                    ]
                )
                table_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Reference URL"),
                        ItemInWidget(itemValue=response_json.get("business_service_intelligence", {})["reference"]),
                    ]
                )
                anomali_enrichment.addWidget(table_widget)
                # Table Widget - Business Service Details End

            # Table Widget #2 Start
            if response_json.get("internet_scanner_intelligence", {}).get("found"):
                table_widget_metadata = TableWidget("Metadata", ["Key", "Value"], columnWidths=["20%", "80%"])
                metadata = response_json.get("internet_scanner_intelligence", {}).get("metadata", {})
                if metadata.get("asn") and metadata.get("asn", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="ASN"),
                            ItemInWidget(itemValue=metadata.get("asn", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("source_city") and metadata.get("source_city", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Source City"),
                            ItemInWidget(itemValue=metadata.get("source_city", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("source_country") and metadata.get("source_country", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Source Country"),
                            ItemInWidget(itemValue=metadata.get("source_country", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("source_country_code") and metadata.get("source_country_code", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Source Country Code"),
                            ItemInWidget(itemValue=metadata.get("source_country_code", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("destination_countries") and metadata.get("destination_countries", []) != []:
                    dest_countries = ", ".join(metadata.get("destination_countries"))
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Destination Countries"),
                            ItemInWidget(itemValue=dest_countries or "Unknown"),
                        ]
                    )
                if metadata.get("destination_country_codes") and metadata.get("destination_country_codes", []) != []:
                    dest_country_codes = ", ".join(metadata.get("destination_country_codes", []))
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Destination Country Codes"),
                            ItemInWidget(itemValue=dest_country_codes or "Unknown"),
                        ]
                    )
                if metadata.get("region") and metadata.get("region", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Region"),
                            ItemInWidget(itemValue=metadata.get("region", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("latitude") and metadata.get("latitude", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Latitude"),
                            ItemInWidget(itemValue=metadata.get("latitude", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("longitude") and metadata.get("longitude", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Longitude"),
                            ItemInWidget(itemValue=metadata.get("longitude", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("sensor_hits") and metadata.get("sensor_hits", "0") != "0":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Sensor Hits"),
                            ItemInWidget(itemValue=metadata.get("sensor_hits", "0") or "0"),
                        ]
                    )
                if metadata.get("sensor_count") and metadata.get("sensor_count", []) != []:
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Sensor Count"),
                            ItemInWidget(itemValue=metadata.get("sensor_count", "0") or "0"),
                        ]
                    )
                if metadata.get("organization") and metadata.get("organization", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Organization"),
                            ItemInWidget(itemValue=metadata.get("organization", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("category") and metadata.get("category", "unknown") != "unknown":
                    table_widget_metadata.addRowOfItems(
                        [
                            ItemInWidget(itemValue="Category"),
                            ItemInWidget(itemValue=metadata.get("category", "Unknown") or "Unknown"),
                        ]
                    )
                anomali_enrichment.addWidget(table_widget_metadata)
                # Table Widget #2 End

                # Table Widget #3 Start
                table_widget_additional = TableWidget("Additional", ["Key", "Value"], columnWidths=["20%", "80%"])
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Known Tor Exit Node"),
                        ItemInWidget(
                            itemValue=str(
                                response_json.get("internet_scanner_intelligence", {}).get("tor", "False")
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
                                response_json.get("internet_scanner_intelligence", {}).get("spoofable", "False")
                            ).capitalize()
                            or "False"
                        ),
                    ]
                )
                if metadata.get("rdns") and metadata.get("rdns", "unknown") != "unknown":
                    table_widget_additional.addRowOfItems(
                        [
                            ItemInWidget(itemValue="rDNS"),
                            ItemInWidget(itemValue=metadata.get("rdns", "Unknown") or "Unknown"),
                        ]
                    )
                if metadata.get("os") and metadata.get("os", "unknown") != "unknown":
                    table_widget_additional.addRowOfItems(
                        [
                            ItemInWidget(itemValue="OS"),
                            ItemInWidget(itemValue=metadata.get("os", "Unknown") or "Unknown"),
                        ]
                    )
                table_widget_additional.addRowOfItems(
                    [
                        ItemInWidget(itemValue="VPN"),
                        ItemInWidget(
                            itemValue=str(
                                response_json.get("internet_scanner_intelligence", {}).get("vpn", "False")
                            ).capitalize()
                            or "False"
                        ),
                    ]
                )
                if response_json.get("internet_scanner_intelligence", {}).get("vpn", "False") == "True":
                    table_widget_additional.addRowOfItems(
                        [
                            ItemInWidget(itemValue="VPN Service"),
                            ItemInWidget(
                                itemValue=response_json.get("internet_scanner_intelligence", {}).get(
                                    "vpn_service", "Unknown"
                                )
                                or "Unknown"
                            ),
                        ]
                    )

                # Create composite_item for TextWidget
                # always declare a new CompositeItem before using it
                port_composite_item = CompositeItem(onSeparateLines=False)
                scan_data = response_json.get("internet_scanner_intelligence", {}).get("raw_data", {}).get("scan", [])
                port_list = []
                if scan_data != []:
                    for item in scan_data[:10]:
                        port_list.append(str(item["port"]) + "/" + str(item["protocol"]))
                if port_list:
                    for port in port_list:
                        port_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, port))

                    if len(scan_data) > 10:
                        port_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(scan_data))
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
                tags = response_json.get("internet_scanner_intelligence", {}).get("tags", [])
                tag_names = []
                for tag in tags[:10]:
                    tag_names.append(tag["name"])
                tag_list = []
                if tags != []:
                    tag_list = tag_names[:10]
                if tag_list:
                    for tag in tag_list:
                        tag_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(tag)))
                    if len(tags) > 10:
                        tag_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(tags))
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
                if response_json.get("internet_scanner_intelligence", {}).get("cves", []) != []:
                    cve_list = response_json.get("internet_scanner_intelligence", {}).get("cves", [])[:10]
                if cve_list:
                    for cve in cve_list:
                        cve_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(cve)))
                    if len(cve_list) > 10:
                        cve_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(cve_list))
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
                ua_list = (
                    response_json.get("internet_scanner_intelligence", {})
                    .get("raw_data", {})
                    .get("http", {})
                    .get("useragent", [])
                )
                if ua_list != []:
                    for ua in ua_list[:10]:
                        ua_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(ua)))
                    if len(ua_list) > 10:
                        ua_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(ua_list))
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
                paths_list = (
                    response_json.get("internet_scanner_intelligence", {})
                    .get("raw_data", {})
                    .get("http", {})
                    .get("path", [])
                )
                if paths_list != []:
                    for path in paths_list[:10]:
                        path_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(path)))
                    if len(paths_list) > 10:
                        path_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(paths_list))
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

                ja4_composite_item = CompositeItem(onSeparateLines=False)
                ja4_list = (
                    response_json.get("internet_scanner_intelligence", {})
                    .get("raw_data", {})
                    .get("tls", [])
                    .get("ja4", [])
                )
                if ja4_list != []:
                    for ja4 in ja4_list[:10]:
                        ja4_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(ja4)))
                    if len(ja4_list) > 10:
                        ja4_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(paths_list))
                                ),
                            )
                        )

                    table_widget_additional.addRowOfItems(
                        [ItemInWidget(ItemTypes.String, "JA4(s)"), ja4_composite_item]
                    )
                else:
                    table_widget_additional.addRowOfItems(
                        [
                            ItemInWidget(ItemTypes.String, "JA4(s)"),
                            ItemInWidget(ItemTypes.String, "None"),
                        ]
                    )

                ja3_composite_item = CompositeItem(onSeparateLines=False)
                ja3_list = response_json.get("internet_scanner_intelligence", {}).get("raw_data", {}).get("ja3", [])
                if ja3_list != []:
                    ja3s = []
                    for item in ja3_list[:10]:
                        ja3s.append(str(item["fingerprint"]) + " / " + str(item["port"]))
                    for ja3 in ja3s:
                        ja3_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, ja3))
                    if len(ja3_list) > 10:
                        ja3_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(ja3_list))
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
                hassh_list = response_json.get("internet_scanner_intelligence", {}).get("raw_data", {}).get("hassh", [])
                if hassh_list != []:
                    hasshs = []
                    for item in hassh_list[:10]:
                        hasshs.append(str(item["fingerprint"]) + " / " + str(item["port"]))
                    for hassh in hasshs:
                        hassh_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, hassh))
                    if len(hassh_list) > 10:
                        hassh_composite_item.addItemInWidget(
                            ItemInWidget(
                                ItemTypes.String,
                                "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                    str(len(hassh_list))
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

        elif response.status_code == 400:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Invalid IP Address",
                        "Invalid IP Address",
                        "#FFFFFF",
                        "#FFA500",
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
                        "The input '%s' is not a valid public IPv4 address. "
                        "Please provide a valid public IPv4 address (e.g., 8.8.8.8). "
                        "Note: GreyNoise only tracks public IPv4 addresses." % search_string,
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("Invalid IPv4 address format: %s" % search_string)
            anomali_enrichment.addMessage("ERROR", "Invalid IPv4 address format: %s" % search_string)
        elif response.status_code == 401:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "API Key Error",
                        "API Key Error",
                        "#FFFFFF",
                        "#FF0000",
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
                        "Your GreyNoise API key is missing, expired, or incorrect. Please verify your API key.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Key is Missing, Expired or Incorrect, please verify")
            anomali_enrichment.addMessage("ERROR", "API Key is Missing, Expired or Incorrect, please verify")
        elif response.status_code == 403:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "API Access Denied",
                        "API Access Denied",
                        "#FFFFFF",
                        "#FF0000",
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
                        "Your GreyNoise API key does not have permission to access this resource. "
                        "Please check your subscription level or contact GreyNoise support.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Access Forbidden - insufficient permissions")
            anomali_enrichment.addMessage("ERROR", "API Access Forbidden - insufficient permissions")
        elif response.status_code == 404:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "IP Not Observed by GreyNoise",
                        "IP Not Observed by GreyNoise",
                        "#FFFFFF",
                        "#808080",
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
                        "The IP address %s has not been observed scanning the Internet by GreyNoise." % search_string,
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
        elif response.status_code == 429:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Rate Limit Reached",
                        "Rate Limit Reached",
                        "#FFFFFF",
                        "#FFA500",
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
                        "You have reached your daily query limit with GreyNoise. "
                        "Please try again tomorrow or contact GreyNoise to upgrade your plan.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Rate-Limit Reached, Please try again tomorrow.")
            anomali_enrichment.addMessage("ERROR", "API Rate-Limit Reached, Please try again tomorrow.")
        elif response.status_code == 500:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise API Error",
                        "GreyNoise API Error",
                        "#FFFFFF",
                        "#FF0000",
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
                        "An error occurred with the GreyNoise API. Please contact GreyNoise support for assistance.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException(
                "An error occurred with the GreyNoise API, please contact GreyNoise for " "assistance."
            )
            anomali_enrichment.addMessage(
                "ERROR", "An error occurred with the GreyNoise API, please contact " "GreyNoise for assistance. "
            )
        else:
            # Handle any other status codes
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Unexpected Response",
                        "Unexpected Response",
                        "#FFFFFF",
                        "#808080",
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
                        "Received unexpected response from GreyNoise API (Status Code: %s). Please try again later."
                        % response.status_code,
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("Unexpected API response: %s" % response.status_code)
            anomali_enrichment.addMessage("ERROR", "Unexpected API response: %s" % response.status_code)
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIP Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
        anomali_enrichment.addMessage(
            "ERROR", "An Unexpected error occurred, please try again. If the error persists please contact support."
        )
    return anomali_enrichment


def enrichIPTimeline(anomali_enrichment, search_string):  # noqa: C901
    """
    Enrich an IP address with historical timeline data from GreyNoise.

    This function queries the GreyNoise timeline API for historical activity data about an IP
    address over the last 30 days. It creates a comprehensive timeline table showing daily
    activity across multiple fields (classification, tags, rDNS, organization, ASN, ports,
    web paths, and user agents) as well as an interactive XRange chart visualization.

    The function uses multi-threaded API calls to fetch timeline data for multiple fields
    in parallel, significantly improving performance compared to sequential requests.

    Args:
        anomali_enrichment (AnomaliEnrichment): The Anomali enrichment object to add widgets to.
        search_string (str): The IP address to get timeline data for.

    Returns:
        AnomaliEnrichment: The enrichment object with added timeline widgets and charts.

    Widgets Created (when data available):
        - Header: GreyNoise Timeline Details for {IP}
        - Text: Description of 30-day daily summary
        - Link: View IP Timeline Details on GreyNoise Visualizer
        - Table: IP Timeline with columns for:
            * Date (formatted as "d Mon YYYY")
            * Classification (malicious/benign/suspicious/unknown)
            * Tags (CompositeItem, max 10 items)
            * rDNS (reverse DNS)
            * Organization
            * ASN (Autonomous System Number)
            * Ports (CompositeItem, max 10 items)
            * Web Paths (CompositeItem, max 10 items)
            * User Agents (CompositeItem, max 10 items)
        - Chart: XRange timeline visualization showing:
            * Classification changes over time (color-coded)
            * rDNS changes over time
            * ASN changes over time

    Features:
        - Parallel API Requests: Uses ThreadPoolExecutor (8 workers) for fast data retrieval
        - Tag Resolution: Automatically converts tag IDs to human-readable names
        - Data Limiting: Composite fields limited to 10 items with overflow indicator
        - Timeline Consolidation: Merges data from multiple field endpoints by timestamp
        - Color Coding: Visual indicators for classifications (red=malicious, green=benign, etc.)
        - Date Formatting: Converts ISO timestamps to readable format

    API Requirements:
        - Enterprise API key (Community keys not supported)
        - Timeline access (certain subscription levels)

    Error Handling:
        - Community API: Shows "Not Supported with Community API Key" message
        - 401: API key authentication error
        - 403: Insufficient subscription level for timeline access
        - 429: Rate limit reached
        - Other: Generic API error message
        - No Data: "No timeline data available" informational message

    Technical Details:
        - Queries 8 fields: destination_port, http_path, http_user_agent, source_asn,
          source_org, source_rdns, tag_ids, classification
        - Granularity: 1 day
        - Time Range: Last 30 days
        - Uses greynoise_timeline.get_greynoise_timeline() function
        - Fallback to error message if timeline function unavailable

    Example:
        >>> enrichment = AnomaliEnrichment()
        >>> enrichIPTimeline(enrichment, "8.8.8.8")
        # Returns enrichment with 30-day timeline table and chart
    """
    try:
        # Use the new threaded timeline function if available
        timeline_data = None
        timeline_error = None

        if get_greynoise_timeline:
            try:
                timeline_data = get_greynoise_timeline(
                    ip=search_string,
                    api_key=api_key,
                    days=30,
                    granularity="1d",
                    max_workers=8,
                    user_agent=USER_AGENT,
                )
            except Exception as e:
                timeline_error = str(e)

        if timeline_data and len(timeline_data) > 0:
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
                        "https://viz.greynoise.io/ip/%s?view=timeline" % search_string,
                        "View IP Timeline Details on GreyNoise Visualizer",
                    ),
                    True,
                )
            )
            # Table Widget #5 Start
            table_widget_timeline = TableWidget(
                "IP Timeline",
                columnHeadings=[
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
                columnTypes=[
                    ItemTypes.Date,
                    ItemTypes.String,
                    ItemTypes.Composite,
                    ItemTypes.String,
                    ItemTypes.String,
                    ItemTypes.String,
                    ItemTypes.Composite,
                    ItemTypes.Composite,
                    ItemTypes.Composite,
                ],
                columnWidths=["8%", "8%"],
            )
            xrange_data = []
            asn_dict = {}
            rdns_dict = {}
            colors = ["gray", "blue", "purple", "orange", "black"]

            # Process the new timeline data format
            for activity in reversed(timeline_data):
                # Extract date and format it
                date = activity.get("Date", "").split("T")[0]
                date_object = datetime.datetime.strptime(date, "%Y-%m-%d").date()
                date_formatted = date_object.strftime("%-d %b %Y")

                # Extract and format fields (all are lists in the new format)
                # Use CompositeItem to display each item on a separate line (limited to 10 items)
                tags_list = activity.get("Tags", [])
                tags_composite_item = CompositeItem(onSeparateLines=True)
                for tag in tags_list[:10]:
                    tags_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, tag))
                if len(tags_list) > 10:
                    tags_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(tags_list))
                            ),
                        )
                    )

                ports_list = activity.get("Ports", [])
                ports_composite_item = CompositeItem(onSeparateLines=True)
                for port in ports_list[:10]:
                    ports_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, port))
                if len(ports_list) > 10:
                    ports_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(ports_list))
                            ),
                        )
                    )

                paths_list = activity.get("Web Paths", [])
                paths_composite_item = CompositeItem(onSeparateLines=True)
                for path in paths_list[:10]:
                    paths_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, path))
                if len(paths_list) > 10:
                    paths_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(paths_list))
                            ),
                        )
                    )

                user_agents_list = activity.get("User Agents", [])
                user_agents_composite_item = CompositeItem(onSeparateLines=True)
                for user_agent in user_agents_list[:10]:
                    user_agents_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, user_agent))
                if len(user_agents_list) > 10:
                    user_agents_composite_item.addItemInWidget(
                        ItemInWidget(
                            ItemTypes.String,
                            "Output limited to 10 of {} items, see Visualizer for more details.".format(
                                str(len(user_agents_list))
                            ),
                        )
                    )

                classification_list = activity.get("Classification", [])
                classification = classification_list[0] if classification_list else ""

                rdns_list = activity.get("rDNS", [])
                rdns = rdns_list[0] if rdns_list else ""

                organization_list = activity.get("Organization", [])
                organization = organization_list[0] if organization_list else ""

                asn_list = activity.get("ASN", [])
                asn = asn_list[0] if asn_list else ""

                # Add row to table
                table_widget_timeline.addRowOfItems(
                    [
                        ItemInWidget(itemValue=date_formatted),
                        ItemInWidget(itemValue=classification),
                        tags_composite_item,
                        ItemInWidget(itemValue=rdns),
                        ItemInWidget(itemValue=organization),
                        ItemInWidget(itemValue=asn),
                        ports_composite_item,
                        paths_composite_item,
                        user_agents_composite_item,
                    ]
                )

                # Build xrange chart data
                start_date = datetime.datetime.strptime(date, "%Y-%m-%d")
                end_date = start_date + datetime.timedelta(days=1)
                start_date = int(start_date.timestamp()) * 1000
                end_date = int(end_date.timestamp()) * 1000

                if classification:
                    if classification == "benign":
                        color = "green"
                    elif classification == "malicious":
                        color = "red"
                    elif classification == "suspicious":
                        color = "yellow"
                    else:
                        color = "gray"
                    classification_data = {
                        "x": start_date,
                        "x2": end_date,
                        "y": 0,
                        "color": color,
                        "value": "Classification: " + classification,
                    }
                    xrange_data.append(classification_data)

                if rdns:
                    if rdns not in rdns_dict.keys():
                        rdns_dict[rdns] = colors[len(rdns_dict) % len(colors)]
                    rdns_data = {
                        "x": start_date,
                        "x2": end_date,
                        "y": 1,
                        "color": rdns_dict[rdns],
                        "value": "rDNS: " + rdns,
                    }
                    xrange_data.append(rdns_data)

                if asn:
                    if asn not in asn_dict.keys():
                        asn_dict[asn] = colors[len(asn_dict) % len(colors)]
                    asn_data = {
                        "x": start_date,
                        "x2": end_date,
                        "y": 2,
                        "color": asn_dict[asn],
                        "value": "ASN: " + asn,
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
        elif timeline_error:
            # Handle errors from the timeline function
            if "401" in timeline_error or "Unauthorized" in timeline_error:
                anomali_enrichment.addMessage("ERROR", "API Key is Missing, Expired or Incorrect, please verify")
            elif "403" in timeline_error or "Forbidden" in timeline_error:
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
            elif "429" in timeline_error or "Rate" in timeline_error:
                anomali_enrichment.addMessage("ERROR", "API Rate-Limit Reached, Please try again tomorrow.")
            else:
                anomali_enrichment.addMessage(
                    "ERROR", "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
                )
        else:
            # No data returned and no error - likely no timeline data available
            anomali_enrichment.addMessage("INFO", "No timeline data available for this IP address.")
    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichIPTimeline Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
        anomali_enrichment.addMessage(
            "ERROR", "An Unexpected error occurred, please try again. If the error persists please contact support."
        )

    return anomali_enrichment


def enrichVulnerability(anomali_enrichment, search_string):  # noqa: C901
    """
    Enrich a CVE vulnerability with intelligence data from GreyNoise.

    This function queries the GreyNoise API for vulnerability intelligence data about a specific
    CVE identifier, providing information about whether the vulnerability is being actively
    exploited in the wild by internet scanners and attackers.

    Args:
        anomali_enrichment (AnomaliEnrichment): The Anomali enrichment object to add widgets to.
        search_string (str): The CVE identifier to query (e.g., "CVE-2024-1234").

    Returns:
        AnomaliEnrichment: The enrichment object with added vulnerability intelligence widgets.

    Widgets Created:
        - Header: GreyNoise Vulnerability Enrichment
        - Table: Vulnerability intelligence data

    Example:
        >>> enrichVulnerability(anomali_enrichment, "CVE-2024-1234")
    """
    anomali_enrichment.addMessage("INFO", "Enriching Vulnerability: %s" % search_string)
    search_string = search_string[0] if isinstance(search_string, list) else search_string
    try:
        response = requests.get(
            api_base + "v1/cve/" + search_string,
            headers={
                "Accept": "application/json",
                "key": api_key,
                "User-Agent": USER_AGENT,
            },
        )
        response_json = response.json()

        if response.status_code == 200:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise Vulnerability Intel for %s" % search_string,
                        "GreyNoise Vulnerability Intel for %s" % search_string,
                        "#A9A9A9",
                        "#FFFFFF",
                        "35px",
                        "bold",
                    ),
                    True,
                )
            )

            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.Link,
                        "https://viz.greynoise.io/cves/%s" % search_string,
                        "View Vulnerability Details on GreyNoise Visualizer",
                    ),
                    True,
                )
            )
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.Link,
                        f"./search?q=(status%20%3D%20%22active%22)%20AND%20"
                        f"(tags%20%3D%20%22vulnerability:{search_string}%22)",
                        "View tagged Observables in ThreatStream",
                    ),
                    True,
                )
            )
            # Table 1: Vulnerability Details
            details = response_json.get("details", {})
            if details and details != {}:
                vuln_details_widget = TableWidget(
                    "Vulnerability Details",
                    ["Name", "Value"],
                    columnWidths=["20%", "80%"],
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Vulnerability Name", itemLabel="Vulnerability Name"),
                        ItemInWidget(
                            itemValue=details.get("vulnerability_name", ""),
                            itemLabel=details.get("vulnerability_name", ""),
                        ),
                    ]
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Vulnerability Description", itemLabel="Vulnerability Description"),
                        ItemInWidget(
                            itemValue=details.get("vulnerability_description", ""),
                            itemLabel=details.get("vulnerability_description", ""),
                        ),
                    ]
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="CVSS Score", itemLabel="CVSS Score"),
                        ItemInWidget(
                            itemValue=str(details.get("cve_cvss_score", "")),
                            itemLabel=str(details.get("cve_cvss_score", "")),
                        ),
                    ]
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Vendor", itemLabel="Vendor"),
                        ItemInWidget(itemValue=details.get("vendor", ""), itemLabel=details.get("vendor", "")),
                    ]
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Product", itemLabel="Product"),
                        ItemInWidget(itemValue=details.get("product", ""), itemLabel=details.get("product", "")),
                    ]
                )
                vuln_details_widget.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Published to NIST NVD", itemLabel="Published to NIST NVD"),
                        ItemInWidget(
                            itemValue=str(details.get("published_to_nist_nvd", "")),
                            itemLabel=str(details.get("published_to_nist_nvd", "")),
                        ),
                    ]
                )
                anomali_enrichment.addWidget(vuln_details_widget)

            # Table 2: Timeline
            timeline = response_json.get("timeline")
            if timeline:
                table_timeline = TableWidget(
                    "Timeline",
                    columnHeadings=["Event", "Date"],
                    columnTypes=[ItemTypes.String, ItemTypes.String],
                )
                cve_published = timeline.get("cve_published_date", "")
                if cve_published:
                    cve_published = cve_published.split("T")[0]
                table_timeline.addRowOfItems(
                    [
                        ItemInWidget(itemValue="CVE Published Date", itemLabel="CVE Published Date"),
                        ItemInWidget(itemValue=cve_published, itemLabel=cve_published),
                    ]
                )

                cve_updated = timeline.get("cve_last_updated_date", "")
                if cve_updated:
                    cve_updated = cve_updated.split("T")[0]
                table_timeline.addRowOfItems(
                    [
                        ItemInWidget(itemValue="CVE Last Updated Date", itemLabel="CVE Last Updated Date"),
                        ItemInWidget(itemValue=cve_updated, itemLabel=cve_updated),
                    ]
                )

                first_published = timeline.get("first_known_published_date", "")
                if first_published:
                    first_published = first_published.split("T")[0]
                table_timeline.addRowOfItems(
                    [
                        ItemInWidget(itemValue="First Known Published Date", itemLabel="First Known Published Date"),
                        ItemInWidget(itemValue=first_published, itemLabel=first_published),
                    ]
                )

                kev_date = timeline.get("cisa_kev_date_added", "")
                if kev_date:
                    kev_date = kev_date.split("T")[0]
                table_timeline.addRowOfItems(
                    [
                        ItemInWidget(itemValue="CISA KEV Date Added", itemLabel="CISA KEV Date Added"),
                        ItemInWidget(itemValue=kev_date, itemLabel=kev_date),
                    ]
                )
                anomali_enrichment.addWidget(table_timeline)

            # Table 3: Exploitation Details
            exploitation = response_json.get("exploitation_details")
            if exploitation:
                table_exploitation = TableWidget(
                    "Exploitation Details",
                    columnHeadings=["Field", "Value"],
                    columnTypes=[ItemTypes.String, ItemTypes.String],
                )
                table_exploitation.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Attack Vector", itemLabel="Attack Vector"),
                        ItemInWidget(
                            itemValue=exploitation.get("attack_vector", ""),
                            itemLabel=exploitation.get("attack_vector", ""),
                        ),
                    ]
                )
                table_exploitation.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Exploit Found", itemLabel="Exploit Found"),
                        ItemInWidget(
                            itemValue=str(exploitation.get("exploit_found", "")),
                            itemLabel=str(exploitation.get("exploit_found", "")),
                        ),
                    ]
                )
                table_exploitation.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Registered in CISA KEV", itemLabel="Registered in CISA KEV"),
                        ItemInWidget(
                            itemValue=str(exploitation.get("exploitation_registered_in_kev", "")),
                            itemLabel=str(exploitation.get("exploitation_registered_in_kev", "")),
                        ),
                    ]
                )
                table_exploitation.addRowOfItems(
                    [
                        ItemInWidget(itemValue="EPSS Score", itemLabel="EPSS Score"),
                        ItemInWidget(
                            itemValue=str(exploitation.get("epss_score", "")),
                            itemLabel=str(exploitation.get("epss_score", "")),
                        ),
                    ]
                )
                anomali_enrichment.addWidget(table_exploitation)

            # Table 4: Exploitation Statistics
            stats = response_json.get("exploitation_stats")
            if stats:
                table_stats = TableWidget(
                    "Exploitation Statistics",
                    columnHeadings=["Metric", "Count"],
                    columnTypes=[ItemTypes.String, ItemTypes.String],
                )
                table_stats.addRowOfItems(
                    [
                        ItemInWidget(
                            itemValue="Number of Available Exploits", itemLabel="Number of Available Exploits"
                        ),
                        ItemInWidget(
                            itemValue=str(stats.get("number_of_available_exploits", "0")),
                            itemLabel=str(stats.get("number_of_available_exploits", "0")),
                        ),
                    ]
                )
                table_stats.addRowOfItems(
                    [
                        ItemInWidget(
                            itemValue="Threat Actors Exploiting Vulnerability",
                            itemLabel="Threat Actors Exploiting Vulnerability",
                        ),
                        ItemInWidget(
                            itemValue=str(stats.get("number_of_threat_actors_exploiting_vulnerability", "0")),
                            itemLabel=str(stats.get("number_of_threat_actors_exploiting_vulnerability", "0")),
                        ),
                    ]
                )
                table_stats.addRowOfItems(
                    [
                        ItemInWidget(
                            itemValue="Botnets Exploiting Vulnerability", itemLabel="Botnets Exploiting Vulnerability"
                        ),
                        ItemInWidget(
                            itemValue=str(stats.get("number_of_botnets_exploiting_vulnerability", "0")),
                            itemLabel=str(stats.get("number_of_botnets_exploiting_vulnerability", "0")),
                        ),
                    ]
                )
                anomali_enrichment.addWidget(table_stats)

            # Table 5: Exploitation Activity
            activity = response_json.get("exploitation_activity")
            if activity:
                if activity.get("activity_seen", False):
                    table_activity = TableWidget(
                        "Exploitation Activity - IPs Observed",
                        columnHeadings=["Time Period", "Benign IPs", "Threat IPs"],
                        columnTypes=[ItemTypes.String, ItemTypes.Link, ItemTypes.Link],
                    )
                else:
                    table_activity = TableWidget(
                        "Exploitation Activity - No IPs Observed",
                        columnHeadings=["Time Period", "Benign IPs", "Threat IPs"],
                        columnTypes=[ItemTypes.String, ItemTypes.String, ItemTypes.String],
                    )
                table_activity.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last 1 Day", itemLabel="Last 1 Day"),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:1d%20AND%20classification:benign"
                            ),
                            itemLabel=str(activity.get("benign_ip_count_1d", "0")),
                        ),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:1d%20AND%20classification:malicious"
                            ),
                            itemLabel=str(activity.get("threat_ip_count_1d", "0")),
                        ),
                    ]
                )
                table_activity.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last 10 Days", itemLabel="Last 10 Days"),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:10d%20AND%20classification:benign"
                            ),
                            itemLabel=str(activity.get("benign_ip_count_10d", "0")),
                        ),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:10d%20AND%20classification:malicious"
                            ),
                            itemLabel=str(activity.get("threat_ip_count_10d", "0")),
                        ),
                    ]
                )
                table_activity.addRowOfItems(
                    [
                        ItemInWidget(itemValue="Last 30 Days", itemLabel="Last 30 Days"),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:30d%20AND%20classification:benign"
                            ),
                            itemLabel=str(activity.get("benign_ip_count_30d", "0")),
                        ),
                        ItemInWidget(
                            itemValue=(
                                f"https://viz.greynoise.io/query/cve:{search_string}%20AND%20"
                                f"last_seen:30d%20AND%20classification:malicious"
                            ),
                            itemLabel=str(activity.get("threat_ip_count_30d", "0")),
                        ),
                    ]
                )
                anomali_enrichment.addWidget(table_activity)
        elif response.status_code == 400:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Invalid CVE Format",
                        "Invalid CVE Format",
                        "#FFFFFF",
                        "#FFA500",
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
                        "The input '%s' is not a valid CVE identifier. "
                        "Please provide a valid CVE in the format CVE-YYYY-NNNNN (e.g., CVE-2024-1234)."
                        % search_string,
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("Invalid CVE format: %s" % search_string)
            anomali_enrichment.addMessage("ERROR", "Invalid CVE format: %s" % search_string)
        elif response.status_code == 401:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "API Key Error",
                        "API Key Error",
                        "#FFFFFF",
                        "#FF0000",
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
                        "Your GreyNoise API key is missing, expired, or incorrect. Please verify your API key.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Key is Missing, Expired or Incorrect, please verify")
            anomali_enrichment.addMessage("ERROR", "API Key is Missing, Expired or Incorrect, please verify")
        elif response.status_code == 403:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "API Access Denied",
                        "API Access Denied",
                        "#FFFFFF",
                        "#FF0000",
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
                        "Your GreyNoise API key does not have permission to access vulnerability intelligence. "
                        "Please check your subscription level or contact GreyNoise support.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Access Forbidden - insufficient permissions for vulnerability data")
            anomali_enrichment.addMessage(
                "ERROR", "API Access Forbidden - insufficient permissions for vulnerability data"
            )
        elif response.status_code == 404:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "The vulnerability %s was not found in the GreyNoise vulnerability database." % search_string,
                    ),
                    True,
                )
            )
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.Link,
                        "https://viz.greynoise.io/cves/%s" % search_string,
                        "View on GreyNoise Visualizer",
                    ),
                    True,
                )
            )
        elif response.status_code == 429:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Rate Limit Reached",
                        "Rate Limit Reached",
                        "#FFFFFF",
                        "#FFA500",
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
                        "You have reached your daily query limit with GreyNoise. "
                        "Please try again tomorrow or contact GreyNoise to upgrade your plan.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("API Rate-Limit Reached, Please try again tomorrow.")
            anomali_enrichment.addMessage("ERROR", "API Rate-Limit Reached, Please try again tomorrow.")
        elif response.status_code == 500:
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "GreyNoise API Error",
                        "GreyNoise API Error",
                        "#FFFFFF",
                        "#FF0000",
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
                        "An error occurred with the GreyNoise API. Please contact GreyNoise support for assistance.",
                    ),
                    True,
                )
            )
            anomali_enrichment.addException(
                "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
            )
            anomali_enrichment.addMessage(
                "ERROR", "An error occurred with the GreyNoise API, please contact GreyNoise for assistance."
            )
        else:
            # Handle any other status codes
            anomali_enrichment.addWidget(
                TextWidget(
                    ItemInWidget(
                        ItemTypes.String,
                        "Unexpected Response",
                        "Unexpected Response",
                        "#FFFFFF",
                        "#808080",
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
                        "Received unexpected response from GreyNoise API (Status Code: %s). Please try again later."
                        % response.status_code,
                    ),
                    True,
                )
            )
            anomali_enrichment.addException("Unexpected API response: %s" % response.status_code)
            anomali_enrichment.addMessage("ERROR", "Unexpected API response: %s" % response.status_code)

    except:  # noqa E722
        anomali_enrichment.addException(
            "enrichVulnerability Unknown Error:%sType: %s%sValue:%s"
            % (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1])
        )
        anomali_enrichment.addMessage(
            "ERROR", "An Unexpected error occurred, please try again. If the error persists please contact support."
        )

    return anomali_enrichment


functions = {
    "enrichIP": enrichIP,
    "enrichIPTimeline": enrichIPTimeline,
    "enrichVulnerability": enrichVulnerability,
}

if __name__ == "__main__":
    anomali_enrichment = AnomaliEnrichment()
    anomali_enrichment.parseArguments()
    transform_name = anomali_enrichment.getTransformName()
    api_key = anomali_enrichment.getCredentialValue("api_key")
    if transform_name == "enrichVulnerability":
        input_cve_values = [x.strip() for x in anomali_enrichment.getFieldValue("cve_list")]
        functions[transform_name](anomali_enrichment, input_cve_values)
    else:
        entity_value = anomali_enrichment.getEntityValue()
        functions[transform_name](anomali_enrichment, entity_value)
    anomali_enrichment.returnOutput()
