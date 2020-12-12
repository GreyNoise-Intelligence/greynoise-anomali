# greynoise-anomali

Initial Build with Anomali Enrichment SDK v2.0

Sample Commandline Test Command:

`python3 greynoise_anomali_enrichment.py enrichIP <enter_ip> --credentials "{\"api_key\":\"<enter_api_key>\"}"`

Bundle Build Process:

- Ensure that metadata.json contains an update version number
- Run `python3 build-bundle.py`
- The bundle file we be created in the bundles directory with format: `greynoise-enrichment-<version>.tar.gz`