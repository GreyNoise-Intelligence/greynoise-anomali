import os
import sys
import copy
import json
import requests

from AnomaliEnrichment import AnomaliEnrichment, TextWidget, ChartWidget, TableWidget, HorizontalRuleWidget, \
    ItemInWidget, ItemTypes, CompositeItem

api_base = "https://api.greynoise.io/v2"
api_key = None

version = "1.0.0"

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

            table_widget = TableWidget("Details", ["Key", "Value"],columnWidths=['20%',
'80%'])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Seen'),
                                        ItemInWidget(itemValue=response_json['seen'])])
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
            table_widget.addRowOfItems([ItemInWidget(itemValue='Actor'),
                                        ItemInWidget(itemValue=response_json['actor'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='ASN'),
                                        ItemInWidget(itemValue=response_json['metadata']['asn'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='City'),
                                        ItemInWidget(itemValue=response_json['metadata']['city'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Country'),
                                        ItemInWidget(itemValue=response_json['metadata']['country'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Country Code'),
                                        ItemInWidget(itemValue=response_json['metadata']['country_code'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Region'),
                                        ItemInWidget(itemValue=response_json['metadata']['region'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Organization'),
                                        ItemInWidget(itemValue=response_json['metadata']['organization'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Category'),
                                        ItemInWidget(itemValue=response_json['metadata']['category'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Tor'),
                                        ItemInWidget(itemValue=response_json['metadata']['tor'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='Spoofable'),
                                        ItemInWidget(itemValue=response_json['spoofable'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='rDNS'),
                                        ItemInWidget(itemValue=response_json['metadata']['rdns'])])
            table_widget.addRowOfItems([ItemInWidget(itemValue='OS'),
                                        ItemInWidget(itemValue=response_json['metadata']['os'])])

            # Create composite_item for TextWidget
            # always declare a new CompositeItem before using it
            port_composite_item = CompositeItem(onSeparateLines=False)
            port_list = []
            if response_json['raw_data']['scan']:
                for item in response_json['raw_data']['scan']:
                    port_list.append(str(item['port']) + '/' + str(item['protocol']))
            for port in port_list[:10]:
                port_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, port, textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            if len(port_list) > 10:
                port_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String,'Output limited to 10 items, see Visualizer for more details.'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String,'Port(s) / Protocol(s)'),port_composite_item])

            tag_composite_item = CompositeItem(onSeparateLines=False)
            tag_list = []
            if response_json['tags']:
                tag_list = response_json['tags']
            for tag in tag_list:
                tag_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(tag), textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, 'Tag(s)'), tag_composite_item])

            cve_composite_item = CompositeItem(onSeparateLines=False)
            cve_list = []
            if response_json['cve']:
                cve_list = response_json['cve']
            for cve in cve_list:
                cve_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(cve), textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, 'CVE(s)'), cve_composite_item])

            ua_composite_item = CompositeItem(onSeparateLines=False)
            ua_list = []
            if 'useragents' in response_json['raw_data']['web']:
                ua_list = response_json['raw_data']['web']['useragents']
            for ua in ua_list:
                ua_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(ua), textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, 'UserAgent String(s)'), ua_composite_item])

            path_composite_item = CompositeItem(onSeparateLines=False)
            paths_list = []
            if 'paths' in response_json['raw_data']['web']:
                paths_list = response_json['raw_data']['web']['paths']
            for path in paths_list:
                path_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, str(path), textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, 'Path(s)'), path_composite_item])

            ja3_composite_item = CompositeItem(onSeparateLines=False)
            ja3_list = []
            if 'ja3' in response_json['raw_data']:
                for item in response_json['raw_data']['ja3']:
                    ja3_list.append(str(item['fingerprint']) + ' / ' + str(item['port']))
            for ja3 in ja3_list:
                ja3_composite_item.addItemInWidget(ItemInWidget(ItemTypes.String, ja3, textColor='#ffffff',
                                                                 backgroundColor='#2D4453', fontSize='small'))

            table_widget.addRowOfItems([ItemInWidget(ItemTypes.String, 'JA3(s)'), ja3_composite_item])

            anomali_enrichment.addWidget(table_widget)

        elif resp_code == 200 and response_json['seen'] == False:
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "GreyNoise Info for %s" % search_string,
                                                                 "#A9A9A9", "#FFFFFF", "30px", "bold"), True))
            anomali_enrichment.addWidget(TextWidget(ItemInWidget(ItemTypes.String,
                                                                 "IP not seen scanning the Internet by GreyNoise in last 90 Days",
                                                                 "IP not seen scanning the Internet by GreyNoise in last 90 Days",
                                                                 "#FFFFFF", "#000000", "15px"), True))
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
