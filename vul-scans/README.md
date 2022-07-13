# Vulnerability Scanning

This action will scan the provided image with [Snyk](https://docs.snyk.io/snyk-cli), 
[Anchore/Grype](https://github.com/anchore/grype) and [Aquasecurity/Trivy](https://github.com/aquasecurity/trivy) 
vulnerability scanners

It will attach the results as a cosign attestation with the results and report the Count of Vulnerabilities found. 


## Usage

```yaml
  - uses: distroless/actions/vul-scans@main
    id: scans
    with:
      # OCI registry where the image is located
      registry: ghcr.io
      # Username for access to the above registry
      username: ${{ github.actor }}
      # Password for access to the above registry
      password: ${{ secrets.GITHUB_TOKEN }}
      # OCI image ref; example  ghcr.io/chainguard-dev/go-demo@sha256:1314268a4d71972ef0c335f7a5e03885cde56ada56276a6224bbf6c5b7903603
      image: ${{ env.IMAGE }}
      # API Token for the Snyk CLI
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      #Should the GitHub action upload the results to GitHub Advance Security portal
      UPLOAD_GITHUB_CODE: true
```

## Scenarios

```yaml
  - uses: distroless/actions/vul-scans@main
    id: scans
    with:
      registry: ghcr.io
      username: ${{ github.actor }}
      password: ${{ secrets.GITHUB_TOKEN }}
      image: ${{ env.IMAGE }}
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      UPLOAD_GITHUB_CODE: true
```

### Verify Attestation

Cosign Verify
```bash
cosign verify-attestation --attachment-tag-prefix trivy ghcr.io/strongjz/go-demo@sha256:8609e13f162895bbee7840c0ab1b709ed67ddf4458c75abe2277fbd7bbc8f719 | jq -r .payload | base64 -d | jq -r .
```

or Rekor CLI, the rekor index is from the Trivy attestation step in GitHub Actions [here](https://github.com/strongjz/go-demo/runs/7235393067?check_suite_focus=true#step:11:386)
```bash
rekor-cli get --log-index 2869438 --format json | jq -r .Attestation | jq -r .
```

<details>

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "cosign.sigstore.dev/attestation/vuln/v1",
  "subject": [
    {
      "name": "ghcr.io/strongjz/go-demo",
      "digest": {
        "sha256": "8609e13f162895bbee7840c0ab1b709ed67ddf4458c75abe2277fbd7bbc8f719"
      }
    }
  ],
  "predicate": {
    "invocation": {
      "parameters": null,
      "uri": "https://github.com/strongjz/go-demo/actions/runs/2630238342",
      "event_id": "",
      "builder.id": "Release Latest Changes"
    },
    "scanner": {
      "uri": "https://github.com/aquasecurity/trivy",
      "version": "0.29.2",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": {
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "runs": [
          {
            "columnKind": "utf16CodeUnits",
            "originalUriBaseIds": {
              "ROOTPATH": {
                "uri": "file:///"
              }
            },
            "results": [],
            "tool": {
              "driver": {
                "fullName": "Trivy Vulnerability Scanner",
                "informationUri": "https://github.com/aquasecurity/trivy",
                "name": "Trivy",
                "rules": [],
                "version": "0.29.2"
              }
            }
          }
        ],
        "version": "2.1.0"
      }
    },
    "metadata": {
      "scanStartedOn": "2022-07-07T14:27:03Z",
      "scanFinishedOn": "2022-07-07T14:27:07Z"
    }
  }
}
```

</details>

### Grype Scan and Attestation

```bash
cosign verify-attestation --attachment-tag-prefix grype- ghcr.io/strongjz/go-demo@sha256:8609e13f162895bbee7840c0ab1b709ed67ddf4458c75abe2277fbd7bbc8f719 | jq -r .payload | base64 -d | jq -r .
```

[Rekor index from the GitHub Action](https://github.com/strongjz/go-demo/runs/7238089696?check_suite_focus=true#step:11:488)

```bash
rekor-cli get --log-index 2872800 --format json | jq -r .Attestation | jq -r .
```

<details>

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "cosign.sigstore.dev/attestation/vuln/v1",
  "subject": [
    {
      "name": "ghcr.io/strongjz/go-demo",
      "digest": {
        "sha256": "8609e13f162895bbee7840c0ab1b709ed67ddf4458c75abe2277fbd7bbc8f719"
      }
    }
  ],
  "predicate": {
    "invocation": {
      "parameters": null,
      "uri": "https://github.com/strongjz/go-demo/actions/runs/2631113049",
      "event_id": "",
      "builder.id": "Release Latest Changes"
    },
    "scanner": {
      "uri": "https://github.com/anchore/grype",
      "version": "0.38.0",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": {
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "runs": [
          {
            "results": [],
            "tool": {
              "driver": {
                "informationUri": "https://github.com/anchore/grype",
                "name": "Grype",
                "version": "0.38.0"
              }
            }
          }
        ],
        "version": "2.1.0"
      }
    },
    "metadata": {
      "scanStartedOn": "2022-07-07T17:01:44Z",
      "scanFinishedOn": "2022-07-07T17:02:00Z"
    }
  }
}
```

</details>


### Trivy Scan and Attestation

```bash
cosign verify-attestation --attachment-tag-prefix trivy- ghcr.io/chainguard-dev/go-demo@sha256:1314268a4d71972ef0c335f7a5e03885cde56ada56276a6224bbf6c5b7903603  | jq -r .payload | base64 -d | jq -r .
```

<details >

```json
Verification for ghcr.io/chainguard-dev/go-demo@sha256:1314268a4d71972ef0c335f7a5e03885cde56ada56276a6224bbf6c5b7903603 --
The following checks were performed on each of these signatures:
- The cosign claims were validated
- Existence of the claims in the transparency log was verified offline
- Any certificates were verified against the Fulcio roots.
Certificate subject:  https://github.com/chainguard-dev/go-demo/.github/workflows/release.yaml@refs/heads/main
Certificate issuer URL:  https://token.actions.githubusercontent.com

{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "cosign.sigstore.dev/attestation/vuln/v1",
  "subject": [
    {
      "name": "ghcr.io/chainguard-dev/go-demo",
      "digest": {
        "sha256": "1314268a4d71972ef0c335f7a5e03885cde56ada56276a6224bbf6c5b7903603"
      }
    }
  ],
  "predicate": {
    "invocation": {
      "parameters": null,
      "uri": "https://github.com/chainguard-dev/go-demo/actions/runs/2663503088",
      "event_id": "",
      "builder.id": "Release Latest Changes"
    },
    "scanner": {
      "uri": "https://github.com/aquasecurity/trivy",
      "version": "0.29.2",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": {
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "runs": [
          {
            "columnKind": "utf16CodeUnits",
            "originalUriBaseIds": {
              "ROOTPATH": {
                "uri": "file:///"
              }
            },
            "results": [],
            "tool": {
              "driver": {
                "fullName": "Trivy Vulnerability Scanner",
                "informationUri": "https://github.com/aquasecurity/trivy",
                "name": "Trivy",
                "rules": [],
                "version": "0.29.2"
              }
            }
          }
        ],
        "version": "2.1.0"
      }
    },
    "metadata": {
      "scanStartedOn": "2022-07-13T12:46:01Z",
      "scanFinishedOn": "2022-07-13T12:46:13Z"
    }
  }
}
```

</details>

[Rekor index from GitHub Action](https://github.com/chainguard-dev/go-demo/runs/7321165006?check_suite_focus=true#step:11:489)

```bash
rekor-cli get --log-index 2932884 --format json | jq -r .Attestation | jq -r . 
```
