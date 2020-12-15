#########################################################################
#
# Anomali CONFIDENTIAL
# __________________
#
#  Copyright 2016 Anomali Inc.
#  All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of Anomali Incorporated and its suppliers,
# if any.  The intellectual and technical concepts contained
# herein are proprietary to Anomali Incorporated
# and its suppliers and may be covered by U.S. and Foreign Patents,
# patents in process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained
# from Anomali Incorporated.
#
#########################################################################


import os
import sys
import copy
import json
import requests

from AnomaliEnrichment import AnomaliEnrichment, TextWidget, ChartWidget, TableWidget, HorizontalRuleWidget, \
    ItemInWidget, ItemTypes, CompositeItem


api_base = "https://www.virustotal.com/vtapi/v2/"
api_key = None

piechart_template_dict = {
    "chart": {
        "height": 300,
        "margin": 0,
        "marginTop": -20,
        "plotBackgroundColor": None,
        "plotBorderWidth": None,
        "backgroundColor": "#fff"
    },
    "credits": {
        "enabled": False
    },
    "title": {
        "text": "Pie Chart Example"
    },
    "tooltip": {
        "headerFormat": "<span style=\"font-size: 10px\">{point.key}</span><br/>",
        "pointFormat": "<b>{point.y} ({point.percentage:.1f}%)</b>"
    },
    "plotOptions": {
        "pie": {
            "allowPointSelect": True,
            "animation": True,
            "cursor": "pointer",
            "innerSize": 100,
            "dataLabels": {
                "enabled": True,
                "format": "{point.prettyName}<br>{point.percentage:.2f} %",
                "style": {
                    "width": "200px"
                }
            },
            "point": {
                "events": {}
            },
            "size": "45%",
            "center": ["50%", "60%"]
        }
    },
    "series": [
        {
            "type": "pie",
            "name": "",
            "data": []
        }
    ]
}

def enrichDomainTabOne(anomali_enrichment, search_string):
    try:
        response = requests.get(api_base + 'domain/report?apikey=' + api_key + '&domain=' + search_string)
        response_json = response.json()
        resp_code = int(response_json['response_code'])
        if resp_code == 1:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "Domain Enrichment for %s" % search_string,
                                                                 "Domain Enrichment for %s" % search_string,
                                                                 "SteelBlue", "White", "large", "bold"), True))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.Link,
                                                                 "https://www.virustotal.com/#/domain/%s" % search_string,
                                                                 "View"), False))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 " comparison"), True))
            if 'resolutions' in response_json:
                table_widget = TableWidget("Resolutions", ["IP Address", "Last Resolved", "Reference"])
                for resolution in response_json['resolutions']:
                    table_widget.addRowOfItems([ItemInWidget(ItemTypes.IPv4,
                                                             resolution['ip_address'],
                                                             resolution['ip_address']),
                                                ItemInWidget(ItemTypes.DateTime,
                                                             resolution['last_resolved'],
                                                             resolution['last_resolved']),
                                                ItemInWidget(ItemTypes.Link,
                                                             "https://www.virustotal.com/#/ip-address/%s" % resolution['ip_address'],
                                                             "detail")])
                anomali_enrichment.addWidget(table_widget)

            # Create HorizontalRuleWidget
            anomali_enrichment.addWidget(HorizontalRuleWidget())

            def create_chart_widget(template_dict, data):
                graph_dict = copy.deepcopy(template_dict)
                # fill in the data
                graph_dict['series'][0]['data'] = data
                graph_json = json.dumps(graph_dict)
                pie_chart_widget = ChartWidget("Requester Distribution", graph_json)
                return pie_chart_widget

            data = [{'y': 0.8, 'prettyName': u'US', 'name': u'US'},
                    {'y': 0.1, 'prettyName': u'DE', 'name': u'DE'},
                    {'y': 0.1, 'prettyName': u'TH', 'name': u'TH'}]
            # Create Pie ChartWidget
            chart_widget = create_chart_widget(piechart_template_dict, data)
            anomali_enrichment.addWidget(chart_widget)

            # Create composite_item for TextWidget
            # always declare a new CompositeItem before using it
            text_composite_item = CompositeItem(onSeparateLines=False)
            port_list = [20, 80, 443]
            for port in port_list:
                text_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(port), textColor='#ffffff',
                                                    backgroundColor='#2D4453', fontSize='medium'))
            port_text_widget = TextWidget(text_composite_item, True)
            anomali_enrichment.addWidget(port_text_widget)

            # Create composite_item for TableWidget
            services_table_widget = TableWidget(tableName='Services', columnHeadings=['Port', 'Service Content'],
                                                columnTypes=[ItemTypes.Integer, ItemTypes.String],
                                                columnWidths=['20%', '80%'])
            # In real world, get data from the API response
            services_data = [{'port': 20, 'lines': ['line1', 'line2', 'line3']},
                             {'port': 80, 'lines': ['line1', 'line2', 'line3']},
                             {'port': 443, 'lines': ['line1', 'line2', 'line3']}]
            for service_data in services_data:
                port = service_data['port']
                # always declare a new CompositeItem before using it
                table_composite_item = CompositeItem(onSeparateLines=True)
                for line in service_data['lines']:
                    table_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, line))
                services_table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, port,
                                                                  textColor='#ffffff', backgroundColor='#2D4453'),
                                                     table_composite_item])
            anomali_enrichment.addWidget(services_table_widget)
    except:
        anomali_enrichment.addException('enrichDomain Unknown Error:%sType: %s%sValue:%s' %
                        (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return anomali_enrichment


def enrichDomainTabTwo(anomali_enrichment, search_string):
    text_widget = TextWidget(ItemInWidget(ItemTypes.String, 'Content for TabTwo', 'Content for TabTwo', "#4682B4",
                                          "#FFFFFF", "30px", "bold"))
    anomali_enrichment.addWidget(text_widget)


def enrichIP(anomali_enrichment, search_string):
    try:
        response = requests.get(api_base + 'ip-address/report?apikey=' + api_key + '&ip=' + search_string)
        response_json = response.json()
        resp_code = int(response_json['response_code'])
        if resp_code == 1:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "IP Enrichment for %s" % search_string,
                                                                 "IP Enrichment for %s" % search_string,
                                                                 "#4682B4", "#FFFFFF", "30px", "bold"), True))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "(Click "), False))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.Link,
                                                                 "https://www.virustotal.com/#/ip-address/%s" % search_string,
                                                                 "here"), False))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 " for comparison)"), True))
            if 'resolutions' in response_json:
                table_widget = TableWidget("Resolutions",
                                           ["Hostname", "Last Resolved", "Reference"],
                                           [ItemTypes.Domain, ItemTypes.DateTime, ItemTypes.Link])
                for resolution in response_json['resolutions']:
                    table_widget.addRowOfItems([ItemInWidget(itemValue=resolution['hostname'],
                                                             backgroundColor="LightSkyBlue",
                                                             textColor="DarkOrange"),
                                                ItemInWidget(itemValue=resolution['last_resolved'],
                                                             fontStyleWeight="italic"),
                                                ItemInWidget(itemValue="https://www.virustotal.com/#/domain/%s" % resolution['hostname'],
                                                             itemLabel="detail")])
                anomali_enrichment.addWidget(table_widget)

            # Create HorizontalRuleWidget
            anomali_enrichment.addWidget(HorizontalRuleWidget())

            def create_chat_widget(template_dict, data):
                graph_dict = copy.deepcopy(template_dict)
                # fill in the data
                graph_dict['series'][0]['data'] = data
                graph_json = json.dumps(graph_dict)
                pie_chart_widget = ChartWidget("Requester Distribution", graph_json)
                return pie_chart_widget

            data = [{'y': 0.8, 'prettyName': u'US', 'name': u'US'},
                    {'y': 0.1, 'prettyName': u'DE', 'name': u'DE'},
                    {'y': 0.1, 'prettyName': u'TH', 'name': u'TH'}]
            # Create Pie ChartWidget
            chart_widget = create_chat_widget(piechart_template_dict, data)
            anomali_enrichment.addWidget(chart_widget)
    except:
        anomali_enrichment.addException('enrichIP Unknown Error:%sType: %s%sValue:%s' %
                        (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return anomali_enrichment


functions = {
    'enrichDomainTabOne': enrichDomainTabOne,
    'enrichDomainTabTwo': enrichDomainTabTwo,
    'enrichIP': enrichIP
}


if __name__ == '__main__':
    anomali_enrichment = AnomaliEnrichment()
    anomali_enrichment.parseArguments()
    transform_name = anomali_enrichment.getTransformName()
    entity_value = anomali_enrichment.getEntityValue()
    api_key = anomali_enrichment.getCredentialValue('api_key')

    functions[transform_name](anomali_enrichment, entity_value)
    anomali_enrichment.returnOutput()
