import os
import sys
import copy
import json
import requests

from AnomaliEnrichment import AnomaliEnrichment, TextWidget, ChartWidget, TableWidget, HorizontalRuleWidget, \
    ItemInWidget, ItemTypes, CompositeItem

api_base = "https://api.greynoise.io/v2"
api_key = None

version = "1.0.1"

def enrichIP(anomali_enrichment, search_string):
    try:
        response = requests.get(api_base + '/noise/context/' + search_string,
                                headers={"Accept": "application/json", "key": api_key,
                                         "User-Agent":"greynoise-anomali-enrichment-" + version})
        response_json = response.json()
        resp_code = int(response.status_code)
        if resp_code == 200 and response_json['seen'] == True:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "#A9A9A9", "#FFFFFF", "30px", "bold"), True))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "Click "), False))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.Link,
                                                                 "https://viz.greynoise.io/ip/%s" % search_string,
                                                                 "here"), False))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 " for GreyNoise Visualizer Information"), True))

            # Table Widget #1 Start
            table_widget = TableWidget("Details", ["Key", "Value"],columnWidths=['20%',
'80%'])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Last Seen'),
                                        ItemInWidget(itemValue=response_json['last_seen'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='First Seen'),
                                        ItemInWidget(itemValue=response_json['first_seen'])])
            if response_json['classification'] == 'malicious':
                table_widget.addRowOfItems([ItemInWidget(itemValue='Classification'),
                                            ItemInWidget(itemValue=response_json['classification'],
                                                         backgroundColor="Red", textColor="White")])
            elif response_json['classification'] == 'benign':
                table_widget.addRowOfItems([ItemInWidget(itemValue='Classification'),
                                            ItemInWidget(itemValue=response_json['classification'],
                                                         backgroundColor="#3CB371", textColor="White")])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Classification'),
                                            ItemInWidget(itemValue=response_json['classification'],
                                                         backgroundColor="Grey", textColor="Black")])
            if response_json['actor']:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Actor'),
                                        ItemInWidget(itemValue=response_json['actor'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Actor'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])

            anomali_enrichment.addWidget(table_widget)
            # Table Widget #1 End

            # Table Widget #2 Start
            table_widget_metadata = TableWidget("Metadata", ["Key", "Value"], columnWidths=['20%',
                                                                                  '80%'])

            if response_json['metadata']['asn']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='ASN'),
                                            ItemInWidget(itemValue=response_json['metadata']['asn'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='ASN'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['city']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='City'),
                                            ItemInWidget(itemValue=response_json['metadata']['city'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='City'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['country']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='Country'),
                                            ItemInWidget(itemValue=response_json['metadata']['country'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Country'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['country_code']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='Country Code'),
                                            ItemInWidget(itemValue=response_json['metadata']['country_code'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Country Code'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['region']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='Region'),
                                            ItemInWidget(itemValue=response_json['metadata']['region'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Region'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['organization']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='Organization'),
                                            ItemInWidget(itemValue=response_json['metadata']['organization'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Organization'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['category']:
                table_widget_metadata.addRowOfItems([ItemInWidget(itemValue='Category'),
                                            ItemInWidget(itemValue=response_json['metadata']['category'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Category'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            anomali_enrichment.addWidget(table_widget_metadata)
            # Table Widget #1 End

            # Table Widget #3 Start
            table_widget_additional = TableWidget("Additional", ["Key", "Value"], columnWidths=['20%',
                                                                                  '80%'])

            if response_json['metadata']['tor']:
                table_widget_additional.addRowOfItems([ItemInWidget(itemValue='Tor'),
                                        ItemInWidget(itemValue=response_json['metadata']['tor'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Tor'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['spoofable']:
                table_widget_additional.addRowOfItems([ItemInWidget(itemValue='Spoofable'),
                                        ItemInWidget(itemValue=response_json['spoofable'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='Spoofable'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['rdns']:
                table_widget_additional.addRowOfItems([ItemInWidget(itemValue='rDNS'),
                                        ItemInWidget(itemValue=response_json['metadata']['rdns'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='rDNS'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])
            if response_json['metadata']['os']:
                table_widget_additional.addRowOfItems([ItemInWidget(itemValue='OS'),
                                        ItemInWidget(itemValue=response_json['metadata']['os'])])
            else:
                table_widget.addRowOfItems([ItemInWidget(itemValue='OS'),
                                            ItemInWidget(ItemTypes.String, 'Unknown')])

            # Create composite_item for TextWidget
            # always declare a new CompositeItem before using it
            port_composite_item = CompositeItem(onSeparateLines=False)
            port_list = []
            if response_json['raw_data']['scan']:
                for item in response_json['raw_data']['scan']:
                    port_list.append(str(item['port']) + '/' + str(item['protocol']))
            if port_list:
                for port in port_list[:10]:
                    port_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, port, textColor='#ffffff',
                                                                     backgroundColor='#2D4453', fontSize='small'))

                if len(port_list) > 10:
                    port_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(port_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String,'Port(s) / Protocol(s)'),port_composite_item])
            else:
                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, 'Port(s) / Protocol(s)'), ItemInWidget(ItemTypes.String, 'None')])

            tag_composite_item = CompositeItem(onSeparateLines=False)
            tag_list = []
            if response_json['tags']:
                tag_list = response_json['tags']
            if tag_list:
                for tag in tag_list[:10]:
                    tag_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(tag), textColor='#ffffff',
                                                                     backgroundColor='#2D4453', fontSize='small'))
                if len(tag_list) > 10:
                    tag_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(tag_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'Tag(s)'), tag_composite_item])
            else:
                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, 'Tag(s)'), ItemInWidget(ItemTypes.String, 'None')])

            cve_composite_item = CompositeItem(onSeparateLines=False)
            cve_list = []
            if response_json['cve']:
                cve_list = response_json['cve']
            if cve_list:
                for cve in cve_list[:10]:
                    cve_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(cve), textColor='#ffffff',
                                                                     backgroundColor='#2D4453', fontSize='small'))
                if len(cve_list) > 10:
                    cve_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(cve_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'CVE(s)'), cve_composite_item])
            else:
                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, 'CVE(s)'), ItemInWidget(ItemTypes.String, 'None')])

            ua_composite_item = CompositeItem(onSeparateLines=False)
            ua_list = []
            if 'useragents' in response_json['raw_data']['web']:
                ua_list = response_json['raw_data']['web']['useragents']

            if ua_list:
                for ua in ua_list[:10]:
                    ua_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(ua), textColor='#ffffff',
                                                                     backgroundColor='#2D4453', fontSize='small'))
                if len(ua_list) > 10:
                    ua_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(ua_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'UserAgent String(s)'), ua_composite_item])
            else:
                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, 'UserAgent String(s)'), ItemInWidget(ItemTypes.String, 'None')])

            path_composite_item = CompositeItem(onSeparateLines=False)
            paths_list = []
            if 'paths' in response_json['raw_data']['web']:
                paths_list = response_json['raw_data']['web']['paths']
            if paths_list:
                for path in paths_list[:10]:
                    path_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(path), textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))
                if len(paths_list) > 10:
                    path_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(paths_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'Path(s)'), path_composite_item])
            else:
                table_widget_additional.addRowOfItems(
                    [ItemInWidget(ItemTypes.String, 'Path(s)'), ItemInWidget(ItemTypes.String, 'None')])

            ja3_composite_item = CompositeItem(onSeparateLines=False)
            ja3_list = []
            if 'ja3' in response_json['raw_data']:
                for item in response_json['raw_data']['ja3']:
                    ja3_list.append(str(item['fingerprint']) + ' / ' + str(item['port']))

            if ja3_list:
                for ja3 in ja3_list[:10]:
                    ja3_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, ja3, textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))
                if len(ja3_list) > 10:
                    ja3_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,('Output limited to 10 of {} items, see Visualizer for more details.').format(str(len(ja3_list)))))

                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'JA3(s)'), ja3_composite_item])
            else:
                table_widget_additional.addRowOfItems([ItemInWidget(ItemTypes.String, 'JA3(s)'), ItemInWidget(ItemTypes.String, 'None')])
            anomali_enrichment.addWidget(table_widget_additional)
            # Table Widget #3 End

        elif resp_code == 200 and response_json['seen'] == False:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "#A9A9A9", "#FFFFFF", "30px", "bold"), True))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "IP not seen scanning the Internet by GreyNoise in last 90 Days",
                                                                 "IP not seen scanning the Internet by GreyNoise in last 90 Days",
                                                                 "#FFFFFF", "#000000", "15px"), True))
        else:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "API Returned Status Code: %s.  Check your API Key and "
                                                                 "connection to resolve or contact GreyNoise for assistance."
                                                                 % resp_code,
                                                                 "API Returned Status Code: %s.  Check your API Key and "
                                                                 "connection to resolve or contact GreyNoise for assistance."
                                                                 % resp_code,
                                                                 "#A9A9A9", "#FFFFFF", "10px"), True))
    except:
        anomali_enrichment.addException('enrichIP Unknown Error:%sType: %s%sValue:%s' %
                                        (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return anomali_enrichment


functions = {
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
