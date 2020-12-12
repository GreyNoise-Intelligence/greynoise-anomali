import tarfile
import re
str = open('metadata.json', 'r').read()
match = re.search(r'"version":\s"(.*)",',str)
ver = match.group(1)

filename = 'bundles/greynoise-enrichment-' + ver + '.tar.gz'
tar = tarfile.open(filename, "w:gz")
for name in ["source/greynoise_anomali_enrichment.py", "greynoise.png", "metadata.json","thumbnail.png"]:
    tar.add(name)
tar.close()
