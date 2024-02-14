# Prometheus Netflow Exporter
This is an exporter that exposes information gathered from Netflow for use by the [Prometheus monitoring system](https://prometheus.io/).

Supports Netflow `v5` and `v9`.

## Installation and Usage
Choose between running as a standalone binary or as a [Docker](https://www.docker.com/) container.

### Go Binary
Build:
```shell
go get -d
go build -o netflow_exporter
```

Run:
```shell
./netflow_exporter
```

### Dockerfile
Build:
```shell
docker build . -t netflow_exporter -f ./Dockerfile
```

Run:
```shell
docker container run -p 2055:2055/udp -p 9191:9191 netflow_exporter
```

Add application arguments to the end of the above command as if running the standalone binary to make use of them. For example, add `--telemetry-path=/foo`.

If you would like to change the port for the Netflow listener or the metrics endpoint, change the port arguments for the above Docker command and add the `--netflow.listen-address` and/or the `--web.listen-address` arguments to the end of the above command to pass the arguments to `netflow_exporter`.

## Usage
Visit your Prometheus metrics endpoint: http://localhost:9191/metrics

## Notes
I think that netflow is not a metrics and analytics message.

Label combination is too much to collect.
