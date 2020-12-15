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
import requests

from AnomaliTransform import AnomaliTransform
from AnomaliTransform import EntityTypes


api_base = "https://www.virustotal.com/vtapi/v2/"
api_key = None


def domainToIP(at, search_string):
    try:
        response = requests.get(api_base + 'domain/report?apikey=' + api_key + '&domain=' + search_string)
        response_json = response.json()
        resp_code = int(response_json['response_code'])
        if resp_code == 1:
            if 'resolutions' in response_json:
                for resolutions in response_json['resolutions']:
                    ae = at.addEntity(EntityTypes.IPv4, '%s' % resolutions['ip_address'])
                    ae.addAdditionalField('last_resolved', 'Last Resolved', '%s' % resolutions['last_resolved'])
    except:
        at.addException('domainToIP Unknown Error:%sType: %s%sValue:%s' %
                        (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return at


def ipToDomain(at, search_string):
    try:
        response = requests.get(api_base + 'ip-address/report?apikey=' + api_key + '&ip=' + search_string)
        response_json = response.json()
        resp_code = int(response_json['response_code'])
        if resp_code == 1:
            if 'resolutions' in response_json:
                for resolutions in response_json['resolutions']:
                    ae = at.addEntity(EntityTypes.Domain, '%s' % resolutions['hostname'])
                    ae.addAdditionalField('last_resolved', 'Last Resolved', '%s' % resolutions['last_resolved'])
    except:
        at.addException('ipToDomain Unknown Error:%sType: %s%sValue:%s' %
                        (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return at


functions = {
    'domainToIP': domainToIP,
    'ipToDomain': ipToDomain
}


if __name__ == '__main__':
    at = AnomaliTransform()
    at.parseArguments()
    transform_name = at.getTransformName()
    entity_value = at.getEntityValue()
    api_key = at.getCredentialValue('api_key')

    functions[transform_name](at, entity_value)
    at.returnOutput()
