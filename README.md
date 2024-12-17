[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_pdfid-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-pdfid)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-pdfid)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-pdfid)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-pdfid)](./LICENSE)
# PDFId Service

This Assemblyline service extracts metadata and objects from PDF files using Didier Stevens PDFId (Version 2.7) and PDFParser (Version 7.4) tools.

## Service Details

### Configuration

- ADDITIONAL_KEYS: List of keywords searched for by PDFid
- HEURISTICS: Choose the heuristics plugin to be run during the service execution. Here's the list of plugin to choose from:
    - pdf_id/pdfid/plugin_embeddedfile
    - pdf_id/pdfid/plugin_nameobfuscation
    - pdf_id/pdfid/plugin_suspicious_properties
    - pdf_id/pdfid/plugin_triage
- MAX_PDF_SIZE: Maximum size PDF to be processed by PDFid. This value will be ignore during deep scan

### Execution

The PDFId service will report the following information for each file when present:

#### File Information

##### PDFId

- PDF Header String
- Number of:
    - objects
    - streams
    - endstreams
    - xref
    - trailer
    - startxref
    - '/Page'
    - '/Encrypt'
    - '/Objstm'
    - '/JS'
    - '/Javascript'
    - '/AA'
    - '/OpenAction'
    - '/AcroForm'
    - '/JBIG2Decode'
    - '/RichMedia'
    - '/Launch'
    - '/Colours'
    - '%%EOF'
    - Bytes after %%EOF
- Total entropy
- Entropy inside streams
- Entropy outside streams
- Mod Date (AL tag: file.pdf.date.modified)
- Creation Date (AL tag: file.date.creation)
- Last Modification Date (AL tag: file.date.last_modified)
- Source Modified Date (AL tag: file.pdf.date.source_modified)

##### PDFParser

*Note:* PDFParser will only run on a sample if in deep scan mode, or if PDFId plugins (see below) detected suspicious elements are present in the sample.

- Reports number of:
    - /Comment
    - /XREF
    - /Trailer
    - /StartXref
    - /Indirect object
    - /Catalog
    - /ExtGState
    - /Font
    - /FontDescriptor
    - /Pages

- Extracts PDF Elements:
    - Comments
    - Trailer
    - StartXref

- Extracts Suspicious Elements:
    - Entire Objects (as extracted file) when flagged by PDFId plugins (JBIG2Decode objects will only be extracted in deep scan mode).
    - Specific Object content (in AL result) and will run FrankenStrings Patterns against content to search for IOCs (determined by PDFId plugins).

- ObjStms
    - Service will attempt to reprocess object streams in samples as PDF files to re-run against PDFId and PDFParser analyzers. If in deep scan mode, a maximum of 100 objstms will be reprocessed, otherwise a maximum of two will be reprocessed.

#### PDFId Plugins

PDFId plugins are python scripts used by PDFId service to score suspicious properties based on PDFId results. Plugins can be added to service by users (see configuration above). The following format is required for plugin scripts to work with this AL service:

```python
class cPDFiD[NAME](cPluginParent):
    onlyValidPDF = True
    name = '[NAME OF PLUGIN]'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        # Whether or not hits is used, it must be returned by Score
        self.hits = []

    def Score(self):
        score = 0
        [conditions that might adjust score/self.hits]

        return score, self.hits

    def Instructions(self, score, hits):
        if score == 1000:
            # These messages will show in AL result,
            along with score
            return 'Some message'

        if score == 500:
            return 'Some other message'

        if score == 0:
            return
```
See source code under "pdfid" folder for examples of plugins already used by this service.


## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Pdfid \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-pdfid

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Pdfid

Ce service d'Assemblyline extrait les métadonnées et les objets des fichiers PDF en utilisant les outils PDFId (Version 2.7) et PDFParser (Version 7.4) de Didier Stevens.


## Détails du service

### Configuration
- ADDITIONAL_KEYS : Liste des mots-clés recherchés par PDFid
- HEURISTICS : Choisissez le module d'extension heuristique à exécuter pendant l'exécution du service. Voici la liste des modules d'extension à choisir :
    - pdf_id/pdfid/plugin_embeddedfile
    - pdf_id/pdfid/plugin_nameobfuscation
    - pdf_id/pdfid/plugin_suspicious_properties
    - pdf_id/pdfid/plugin_triage
- MAX_PDF_SIZE : Taille maximale du PDF à traiter par PDFid. Cette valeur est ignorée lors de l'analyse approfondie

### Exécution
Le service PDFId rapporte les informations suivantes pour chaque fichier lorsqu'elles sont présentes :

#### Informations sur le fichier

##### PDFId

- Chaîne de caractère de l'en-tête du PDF
- Nombre de :
    - objects
    - streams
    - endstreams
    - xref
    - trailer
    - startxref
    - '/Page'
    - '/Encrypt'
    - '/Objstm'
    - '/JS'
    - '/Javascript'
    - '/AA'
    - '/OpenAction'
    - '/AcroForm'
    - '/JBIG2Decode'
    - '/RichMedia'
    - '/Launch'
    - '/Colours'
    - '%%EOF'
    - Bytes after %%EOF
- Entropie totale
- Entropie à l'intérieur des flux
- Entropie en dehors des flux
- Date de modification (AL tag : file.pdf.date.modified)
- Date de création (AL tag : file.date.creation)
- Date de la dernière modification (AL tag : file.date.last_modified)
- Date de la modification de la source de données (AL tag : file.pdf.date.source_modified)

##### PDFParser

*Note:* PDFParser n'est exécuté sur un échantillon qu'en mode d'analyse approfondie, ou si les modules d'extension PDFId (voir ci-dessous) ont détecté la présence d'éléments suspicieux dans l'échantillon.

- Signale le nombre de :
    - /Comment
    - /XREF
    - /Trailer
    - /StartXref
    - /Indirect object
    - /Catalog
    - /ExtGState
    - /Font
    - /FontDescriptor
    - /Pages

- Extrait les éléments du PDF :
    - Comments
    - Trailer
    - StartXref

- Extrait les éléments suspicieux :
    - Objets entiers (dans le fichier extrait) lorsqu'ils sont signalés par les modules PDFId (les objets JBIG2Decode ne seront extraits qu'en mode d'analyse approfondie).
    - Le contenu d'un objet spécifique (dans le résultat de l'analyse AL) et l'exécution de motifs FrankenStrings contre le contenu pour rechercher des IOC (déterminés par les plugins PDFId).

- ObjStms
    - Le service tentera de retraiter les flux d'objets dans les échantillons sous forme de fichiers PDF pour les soumettre à nouveau aux analyseurs PDFId et PDFParser. En mode d'analyse approfondie, un maximum de 100 objstms sera retraité, sinon un maximum de deux objstms sera retraité.

#### Plugins PDFId

Les modules d'extension PDFId sont des scripts python utilisés par le service PDFId pour évaluer les propriétés suspicieuses sur la base des résultats PDFId. Les modules d'extension peuvent être ajoutés au service par les utilisateurs (voir la configuration ci-dessus). Le format suivant est requis pour que les scripts des modules d'extension fonctionnent avec ce service AL :

```python
class cPDFiD[NAME](cPluginParent):
    onlyValidPDF = True
    name = '[NAME OF PLUGIN]'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        # Whether or not hits is used, it must be returned by Score
        self.hits = []

    def Score(self):
        score = 0
        [conditions that might adjust score/self.hits]

        return score, self.hits

    def Instructions(self, score, hits):
        if score == 1000:
            # These messages will show in AL result,
            along with score
            return 'Some message'

        if score == 500:
            return 'Some other message'

        if score == 0:
            return
```
Voir le code source dans le dossier "pdfid" pour des exemples de plugins déjà utilisés par ce service.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Pdfid \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-pdfid

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
