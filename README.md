# greynoise-anomali

Initial Build with Anomali Enrichment SDK v2.0

Sample Commandline Test Command:

`python3 greynoise_anomali_enrichment.py enrichIP <enter_ip> --credentials "{\"api_key\":\"<enter_api_key>\"}"`

Bundle Build Process:
- Ensure that metadata.json contains an update version number
- Ensure an updated PDF of the documentation is included in the docs folder, following the naming convention `GreyNoise Enrichment Plugin for Anomali ThreatStream v<version>.pdf`  
- Run `python3 build-bundle.py`
- The bundle file will be created in the bundles directory with format: `greynoise-enrichment-<version>.tar.gz`
- The submission Zip needed to send to Anomali (include the bundle and docs) will be created in the bundles directory with format: `greynoise-enrichment-<version>.zip`

Doc Information:
- Ensure any relavent features or new transforms are added to the document
- Ensure the change log is updated in the document

Certification Submission:
- Email the Zip file for submission to enrichments.sdk@anomali.com