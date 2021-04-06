[![main](https://github.com/GreyNoise-Intelligence/greynoise-anomali/workflows/python_linters/badge.svg)](https://github.com/GreyNoise-Intelligence/greynoise-anomali/actions?query=workflow%3Apython_linters)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# GreyNoise Anomali ThreatStream Enrichment

Initial Build with Anomali Enrichment SDK v2.0

Sample Commandline Test Command:

`python3 greynoise_anomali_enrichment.py enrichIP <enter_ip> --credentials "{\"api_key\":\"<enter_api_key>\"}"`

Bundle Build Process:
- Ensure that metadata.json contains an update version number
- Ensure an updated PDF of the documentation is included in the docs folder, following the naming convention `GreyNoise Enrichment Plugin for Anomali ThreatStream v<version>.pdf`  
- Run `python3 build-bundle.py`
- The bundle file will be created in the `bundles` directory with format: `greynoise-enrichment-<version>.tar.gz`
- The submission Zip needed to send to Anomali (include the bundle and docs) will be created in the bundles directory with format: `greynoise-enrichment-<version>.zip`

Doc Information:
- Ensure any relevant features or new transforms are added to the document
- Ensure the change log is updated in the document

Certification Submission:
- Email the Zip file for submission to enrichments.sdk@anomali.com

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the
[tags on this repository](https://github.com/GreyNoise-Intelligence/greynoise-anomali/tags).

## Authors

* **Brad Chiappetta** - *Initial work* - [BradChiappetta](https://github.com/bradchiappetta)

See also the list of [contributors](https://github.com/GreyNoise-Intelligence/greynoise-anomali/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

## Links

* [GreyNoise.io](https://greynoise.io)
* [GreyNoise Terms](https://greynoise.io/terms)
* [GreyNoise Developer Portal](https://developer.greynoise.io)

## Contact Us

Have any questions or comments on this integration?  Contact us at [integrations@greynoise.io](mailto:integrations@greynoise.io)