import tarfile
import re
from zipfile import ZipFile

str = open("metadata.json", "r").read()
match = re.search(r'"version":\s"(.*)",', str)
metadata_ver = match.group(1)

enrich_str = open("source/greynoise_anomali_enrichment.py", "r").read()
enrich_match = re.search(r"VERSION\s=\s\S(.*)\S", enrich_str)
enrich_ver = enrich_match.group(1)

print("metadata_ver = " + metadata_ver)
print("enrich_ver = " + enrich_ver)
if enrich_ver != metadata_ver:
    with open("source/greynoise_anomali_enrichment.py", "r+") as f:
        text = f.read()
        text = re.sub(
            'VERSION = "' + enrich_ver + '"', 'VERSION = "' + metadata_ver + '"', text
        )
        f.seek(0)
        f.write(text)
        f.truncate()
        print("Enrich file Version Updated to match Metadata")
else:
    print("Enrich file Version matches Metadata")

transform_str = open("source/greynoise_anomali_transform.py", "r").read()
transform_match = re.search(r"VERSION\s=\s\S(.*)\S", transform_str)
transform_ver = transform_match.group(1)

print("metadata_ver = " + metadata_ver)
print("transform_ver = " + transform_ver)
if transform_ver != metadata_ver:
    with open("source/greynoise_anomali_transform.py", "r+") as f:
        text = f.read()
        text = re.sub(
            'VERSION = "' + enrich_ver + '"', 'VERSION = "' + metadata_ver + '"', text
        )
        f.seek(0)
        f.write(text)
        f.truncate()
        print("Transform file Version Updated to match Metadata")
else:
    print("Transform file Version matches Metadata")

filename = "bundles/greynoise-enrichment-" + metadata_ver + ".tgz"
tar = tarfile.open(filename, "w:gz")
for name in [
    "source/greynoise_anomali_enrichment.py",
    "source/greynoise_anomali_transform.py",
    "greynoise.png",
    "metadata.json",
    "thumbnail.png",
]:
    tar.add(name)
tar.close()

zip_file = "bundles/greynoise-enrichment-" + metadata_ver + ".zip"
# create a ZipFile object
zipObj = ZipFile(zip_file, "w")
# Add multiple files to the zip
zipObj.write(filename)
zipObj.write(
    "docs/GreyNoise Enrichment for Anomali ThreatStream v" + metadata_ver + ".pdf"
)
# close the Zip File
zipObj.close()
