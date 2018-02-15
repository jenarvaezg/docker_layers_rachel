# docker_layers_rachel

Small CLI written in golang using Cobra that uses [Rachel Analyzer](https://rachelanalyzer.com) to analyze a public docker image.

If a review of the base (FROM XXX) of the submitted image has been previously analyzed, it is possible to remove vulnerabilities that were also in the base iamge.

