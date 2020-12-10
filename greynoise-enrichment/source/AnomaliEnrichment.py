#!/usr/bin/python


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


import json
import argparse
from abc import ABCMeta, abstractmethod


class ItemTypes(object):
    String = "String"
    Integer = "Integer"
    Float = "Float"
    Date = "Date"
    DateTime = "DateTime"
    Link = "Link"
    Domain = "Domain"
    IPv4 = "IPv4"
    Hash = "Hash"
    Email = "Email"
    URL = "URL"
    Phrase = "Phrase"
    AS = "AS"
    NSRecord = "NSRecord"
    Composite = "Composite"


class BaseItem:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        self.item = {}

    def returnItem(self):
        return self.item

    def __repr__(self):
        return json.dumps(self.item, separators=(',',':'))


class ItemInWidget(BaseItem):
    def __init__(self, itemType=None, itemValue=None, itemLabel=None,
                 backgroundColor=None, textColor=None,
                 fontSize=None, fontStyleWeight=None):
        super(ItemInWidget, self).__init__()
        if itemType is not None:
            self.item['itemType'] = itemType
        else:
            self.item['itemType'] = ItemTypes.String
        if itemValue is not None:
            self.item['itemValue'] = itemValue
        else:
            self.item['itemValue'] = ""
        if itemLabel is not None:
            self.item['itemLabel'] = itemLabel
        elif itemType == ItemTypes.Link:
            self.item['itemLabel'] = self.item['itemValue']

        if backgroundColor is not None:
            self.item['backgroundColor'] = backgroundColor
        if textColor is not None:
            self.item['textColor'] = textColor

        if fontSize is not None:
            self.item['fontSize'] = fontSize
        if fontStyleWeight is not None:
            self.item['fontStyleWeight'] = fontStyleWeight

    def setType(self, itemType=None):
        if itemType is not None:
            self.item['itemType'] = itemType

    def setValue(self, itemValue=None):
        if itemValue is not None:
            self.item['itemValue'] = itemValue

    def setLabel(self, itemLabel=None):
        if itemLabel is not None:
            self.item['itemLabel'] = itemLabel

    def setBackgroundColor(self, backgroundColor=None):
        if backgroundColor is not None:
            self.item['backgroundColor'] = backgroundColor

    def setTextColor(self, textColor=None):
        if textColor is not None:
            self.item['textColor'] = textColor

    def setFontSize(self, fontSize=None):
        if fontSize is not None:
            self.item['fontSize'] = fontSize

    def setFontStyleWeight(self, fontStyleWeight=None):
        if fontStyleWeight is not None:
            self.item['fontStyleWeight'] = fontStyleWeight


class CompositeItem(BaseItem):
    def __init__(self, onSeparateLines=None):
        super(CompositeItem, self).__init__()
        self.item['itemType'] = ItemTypes.Composite
        self.item['itemList'] = []
        if isinstance(onSeparateLines, bool):
            self.item['onSeparateLines'] = onSeparateLines
        else:
            self.item['onSeparateLines'] = True

    def addItemInWidget(self, itemInWidget):
        self.item['itemList'].append(itemInWidget.returnItem())
        return itemInWidget

    def setOnSeparateLines(self, onSeparateLines=None):
        if isinstance(onSeparateLines, bool):
            self.item['onSeparateLines'] = onSeparateLines


class BaseWidget:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        self.widget = {}

    def returnWidget(self):
        return self.widget

    def __repr__(self):
        return json.dumps(self.widget, separators=(',',':'))


class TextWidget(BaseWidget):
    def __init__(self, item=None, lineBreakEnding=None):
        super(TextWidget, self).__init__()
        self.widget['widgetType'] = "Text"
        if isinstance(item, ItemInWidget) or isinstance(item, CompositeItem):
            self.widget['item'] = item.returnItem()
        else:
            self.widget['item'] = ItemInWidget(ItemTypes.String, "", "").returnItem()
        if isinstance(lineBreakEnding, bool):
            self.widget['lineBreakEnding'] = lineBreakEnding
        else:
            self.widget['lineBreakEnding'] = True

    def setItem(self, item=None):
        if item is not None:
            self.widget['item'] = item.returnItem()

    def setLineBreakEnding(self, lineBreakEnding=None):
        if isinstance(lineBreakEnding, bool):
            self.widget['lineBreakEnding'] = lineBreakEnding


class ChartWidget(BaseWidget):
    def __init__(self, chartName=None, highchartsJson=None):
        super(ChartWidget, self).__init__()
        self.widget['widgetType'] = "Chart"
        if chartName is not None:
            self.widget['chartName'] = chartName
        else:
            self.widget['chartName'] = ""
        if highchartsJson is not None:
            self.widget['highchartsJson'] = highchartsJson
        else:
            self.widget['highchartsJson'] = "{}"

    def setChartName(self, chartName=None):
        if chartName is not None:
            self.widget['chartName'] = chartName

    def setHighchartsJson(self, highchartsJson=None):
        if highchartsJson is not None:
            self.widget['highchartsJson'] = highchartsJson


class TableWidget(BaseWidget):
    def __init__(self, tableName=None,
                 columnHeadings=None, columnTypes=None, columnWidths=None):
        super(TableWidget, self).__init__()
        self.widget['widgetType'] = "Table"
        if tableName is not None:
            self.widget['tableName'] = tableName
        else:
            self.widget['tableName'] = ""
        if columnHeadings is not None:
            self.widget['columnHeadings'] = columnHeadings
        else:
            self.widget['columnHeadings'] = []
        if columnTypes is not None:
            self.widget['columnTypes'] = columnTypes
        if columnWidths is not None:
            self.widget['columnWidths'] = columnWidths
        self.widget['rows'] = []

    def setTableName(self, tableName=None):
        if tableName is not None:
            self.widget['tableName'] = tableName

    def setColumnHeadings(self, columnHeadings=None):
        if columnHeadings is not None:
            self.widget['columnHeadings'] = columnHeadings

    def setColumnTypes(self, columnTypes=None):
        if columnTypes is not None:
            self.widget['columnTypes'] = columnTypes

    def setColumnWidths(self, columnWidths=None):
        if columnWidths is not None:
            self.widget['columnWidths'] = columnWidths

    def addRowOfItems(self, listOfItems=None):
        if listOfItems is not None:
            self.widget['rows'].append([item.returnItem() for item in listOfItems])


class HorizontalRuleWidget(BaseWidget):
    def __init__(self):
        super(HorizontalRuleWidget, self).__init__()
        self.widget['widgetType'] = "HorizontalRule"


class AnomaliEnrichment(object):
    def __init__(self):
        self.transformName = None
        self.entityValue = None
        self.entityFields = {}
        self.credentials = {}
        self.enrichment = {}
        self.enrichment['widgets'] = []
        self.enrichment['messages'] = []
        self.enrichment['exceptions'] = []

    def parseArguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--credentials')
        parser.add_argument('positional', nargs='*')
        args = parser.parse_args()
        if args.credentials:
            self.credentials = json.loads(args.credentials)
        if args.positional:
            self.transformName = args.positional[0]
        if len(args.positional) > 1:
            self.entityValue = args.positional[1]
        if len(args.positional) > 2:
            self.entityFields = json.loads(args.positional[2])

    def getTransformName(self):
        return self.transformName

    def getEntityValue(self):
        return self.entityValue

    def getFieldValue(self, fieldName):
        return self.entityFields.get(fieldName)

    def getCredentialValue(self, credentialName):
        return self.credentials.get(credentialName)

    def addWidget(self, widget):
        self.enrichment['widgets'].append(widget.returnWidget())
        return widget

    def addMessage(self, messageType=None, messageText=None):
        self.enrichment['messages'].append({'messageType': messageType,
                                           'messageText': messageText})

    def addException(self, exceptionString):
        self.enrichment['exceptions'].append(exceptionString)

    def returnOutput(self):
        for widget in self.enrichment['widgets']:
            if widget['widgetType'] == "Table" and widget.get('columnTypes'):
                for row in widget['rows']:
                    for item in row:
                        item.pop('itemType', None)
        print(json.dumps(self.enrichment, separators=(',',':')))
