# docker-multiarch

A simple golang program that reads a set of per-architecture docker image manifests
and then generates a multi-architecture manifest list and publishes it back to the
same registry containing the original images.

$ go build -o docker-multiarch main.go
$ ./docker-multiarch
Usage: ./docker-multiarch [-u username] [-p password] destination_image source_image1 source_image2 ...

