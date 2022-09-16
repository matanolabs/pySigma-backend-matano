![Tests](https://github.com/matanolabs/pySigma-backend-matano/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Matano Backend

This is the Matano backend for PySigma. It provides the package `sigma.backends.matano` with the `MatanoPythonBackend` class.

## Overview

This backend will let you convert Sigma rules into [Matano Python detections](https://www.matano.dev/docs/detections). You can use the [sigma-cli](https://github.com/SigmaHQ/sigma-cli) to import existing Sigma rules into Matano detections that are ready to use with Matano.

## Usage

The package supports the following output formats:

* default: plain Matano Python detection
* detection: generates detection directories for your [Matano directory](https://www.matano.dev/docs/matano-directory#detections-directory-detections)

## Notes

This backend is currently maintained by:
* [Matano](https://github.com/matanolabs/)
