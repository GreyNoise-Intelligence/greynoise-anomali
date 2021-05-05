Folder structure and contents:


1. docs:
  - Anomali_Enrichments_SDK_3.0.pdf: Contains prerequisites and instructions for developing, testing, bundling, and deploying enrichment bundles.


2. lib:
  - AnomaliTransform.py: Contains the Anomali Python Transform Library - required for building pivot-based transformations.
  - AnomaliEnrichment.py: Contains the Anomali Python Enrichment Library - required for building context-based enrichment transformations.


3. samples:
  - sampleapp-pivot-enrichment.tgz: Example pivot-based enrichment application developed by Anomali. This sample enrichment bundle can be uploaded to Anomali ThreatStream Platform.
    Run "tar zxvf sampleapp-pivot-enrichment.tgz" to see its contents:
    * metadata.json: Contains metadata for the sample enrichment bundle.
    * thumbnail.png and sampleapp.png: Icons displayed to users on the ThreatStream user interface.
    * source: Folder containing all python scripts developed for the enrichment.
      (Note: All scripts must be in the top level of this folder. Folder hierarchy is not supported.)
      * vt_anomali_transform.py: Example pivot-based enrichment script.
  - sampleapp-context-enrichment.tgz: Example context-based enrichment application developed by Anomali. This sample enrichment bundle can be uploaded to Anomali ThreatStream Platform.
    Run "tar zxvf sampleapp-context-enrichment.tgz" to see its contents:
    * metadata.json : Contains metadata for the sample enrichment bundle.
    * thumbnail.png and virustotal.png : Icons displayed to users on the ThreatStream user interface.
    * source : Folder containing all python scripts developed for the enrichment.
      (Note: All scripts must be in the top level of this folder. Folder hierarchy is not supported.)
      * vt_anomali_enrichment.py: Example context-based enrichment script.
