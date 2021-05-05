#!/usr/bin/python


#########################################################################
#
# Anomali CONFIDENTIAL
# __________________
#
#  Copyright 2021 Anomali Inc.
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


class EntityTypes(object):
    Domain = "anomali.Domain"
    IPv4 = "anomali.IPv4Address"
    Hash = "anomali.Hash"
    EmailAddress = "anomali.EmailAddress"
    URL = "anomali.URL"
    Phrase = "anomali.Phrase"
    AS = "anomali.AS"
    NSRecord = "anomali.NSRecord"


class AnomaliEntity(object):
    def __init__(self, eT=None, eV=None):
        self.entity = {}
        if eT is not None:
            self.entity['entityType'] = eT
        else:
            self.entity['entityType'] = EntityTypes.Phrase
        if eV is not None:
            self.entity['entityValue'] = eV
        else:
            self.entity['entityValue'] = ""
        self.entity['additionalFields'] = []

    def setType(self, eT=None):
        if eT is not None:
            self.entity['entityType'] = eT

    def setValue(self, eV=None):
        if eV is not None:
            self.entity['entityValue'] = eV

    def addAdditionalField(self, fieldName=None, displayName=None, fieldValue=None):
        self.entity['additionalFields'].append({'fieldName': fieldName,
                                                'displayName': displayName,
                                                'fieldValue': fieldValue})

    def returnEntity(self):
        return self.entity

    def __repr__(self):
        return json.dumps(self.entity, separators=(',',':'))


class AnomaliTransform(object):
    def __init__(self):
        self.transformName = None
        self.entityValue = None
        self.entityFields = {}
        self.credentials = {}
        self.transform = {}
        self.transform['entities'] = []
        self.transform['messages'] = []
        self.transform['exceptions'] = []

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

    def addEntity(self, entityType, entityValue):
        ae = AnomaliEntity(entityType, entityValue)
        self.transform['entities'].append(ae.entity)
        return ae

    def addMessage(self, messageType=None, messageText=None):
        self.transform['messages'].append({'messageType': messageType,
                                           'messageText': messageText})

    def addException(self, exceptionString):
        self.transform['exceptions'].append(exceptionString)

    def returnOutput(self):
        print(json.dumps(self.transform, separators=(',', ':')), end=' ')
