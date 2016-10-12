# Prometheus netflow Exporter
This is an exporter that exposes information gathered from netflow for use by the Prometheus monitoring system.

now support netflow v9 only

## Installation
go get -d

go build

## Usage
```
./netflow_exporter
```
Visit http://localhost:9191/metrics

