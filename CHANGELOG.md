## 2.4.0
  - Updates to support SDK 3.1 and use tabbed layout
  - Add IP Similarity enrichment
  - Add IP Timeline enrichment
  - Add IP Destination Geo Information
  - Renames Country and Country Code to Source Country and Source Country Code
  - Fixes Viz hyperlinks

## 2.3.0
  - Updates to metadata to define output types

## 2.2.0
  - Updated enrichment to hide some attributes when value is unknown to streamline the output
  - Updated base URL for links to Visualizer
  - Updated terminology around RIOT IPs for clarity
  - Added RIOT Trust Level values

## 2.1.0
  - Add support for GreyNoise Community API usage

## 2.0.0
  - Add Pivot-Based Enrichment

## 1.1.0
  - Add support for Rule It Out (RIOT) IP Lookups

## 1.0.4
  - Add error handling for bad / missing API key

## 1.0.3
  - Code improvements
  - Added missing VPN/VPN_Service and HASSH fields

## 1.0.2
  - Code improvements

## 1.0.1
  - Removed "seen" from table view as all returned results are seen
  - Split data into 3 tables to help with analyst review of data
  - Limited results to 10 for all list fields and included message on total number of results found
  - Replaced blank response with "None" or "Unknown", where applicable
  - Added better error handling for non-200 response

## 1.0.0
  - Plugin created with the based on SDK v2.0