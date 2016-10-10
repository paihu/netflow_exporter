package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/netflow5"
	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/session"
)

var (
	showVersion    = flag.Bool("version", false, "Print version information.")
	netflowAddress = flag.String("netflow.listen-address", ":2055", "Network address on which to accept netflow binary network packets, e.g. \":2055\".")
	listenAddress  = flag.String("web.listen-address", ":9200", "Address on which to expose metrics.")
	metricsPath    = flag.String("web.telemetry-path", "/metrics", "Path under which to expose Prometheus metrics.")
	sampleExpiry   = flag.Duration("netflow.sample-expiry", 5*time.Minute, "How long a sample is valid for.")
	lastProcessed  = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "netflow_last_processed_timestamp_seconds",
			Help: "Unix timestamp of the last processed netflow metric.",
		},
	)
)

type netflowSample struct {
	Labels      map[string]string
	Counts      map[string]float64
	TimestampMs int64
}
type netflowCollector struct {
	ch      chan *netflowSample
	samples map[string]*netflowSample
	mu      *sync.Mutex
}

func newNetflowCollector() *netflowCollector {
	c := &netflowCollector{
		ch:      make(chan *netflowSample, 0),
		samples: map[string]*netflowSample{},
		mu:      &sync.Mutex{},
	}
	go c.processSamples()
	return c
}

func (c *netflowCollector) processReader(r io.Reader) {
	d := netflow.NewDecoder(session.New())
	m, err := d.Read(r)
	if err != nil {
		log.Infoln("netflow Packet Decord Error : %s", err)
	}

	switch p := m.(type) {
	case *netflow5.Packet:
		netflow5.Dump(p)
	case *netflow9.Packet:
		for key, value := range p.DataFlowSets {
			log.Infoln("key:", key, "value:", value)
		}
	}
}

func (c *netflowCollector) processSamples() {
	ticker := time.NewTicker(time.Minute).C
	for {
		select {
		case sample := <-c.ch:
			log.Infoln("add samples", sample.Labels)
			c.mu.Lock()
			c.samples[fmt.Sprintf("%s", sample.Labels)] = sample
			c.mu.Unlock()
		case <-ticker:
			ageLimit := int64(float64(time.Now().Add(-*sampleExpiry).UnixNano()) / 1e9)
			c.mu.Lock()
			for k, sample := range c.samples {
				if ageLimit >= sample.TimestampMs {
					delete(c.samples, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *netflowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lastProcessed.Desc()
}

func (c *netflowCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- lastProcessed
	c.mu.Lock()
	samples := make([]*netflowSample, 0, len(c.samples))
	for _, sample := range c.samples {
		samples = append(samples, sample)
	}
	c.mu.Unlock()
	ageLimit := int64(float64(time.Now().Add(-*sampleExpiry).UnixNano()) / 1e9)
	for _, sample := range samples {
		if ageLimit >= sample.TimestampMs {
			continue
		}
		for key, value := range sample.Counts {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(fmt.Sprintf("netflow_%s", key), fmt.Sprintf("netflow metric %s", key), []string{}, sample.Labels),
				prometheus.GaugeValue,
				value)
		}
	}
}

func NewTimeConstMetric(desc *prometheus.Desc, valueType prometheus.ValueType, value float64, sample netflowSample, timestamp int64) (prometheus.Metric, error) {
	return &timeConstMetric{
		timestamp:  timestamp,
		desc:       desc,
		valType:    valueType,
		val:        value,
		labelPairs: makeLabelPair(sample),
	}, nil
}
func MustNewTimeConstMetric(desc *prometheus.Desc, valueType prometheus.ValueType, value float64, sample netflowSample, timestamp int64) prometheus.Metric {
	m, err := NewTimeConstMetric(desc, valueType, value, sample, timestamp)
	if err != nil {
		panic(err)
	}

	return m
}

type timeConstMetric struct {
	timestamp  int64
	desc       *prometheus.Desc
	valType    prometheus.ValueType
	val        float64
	labelPairs []*dto.LabelPair
}

func makeLabelPair(sample netflowSample) []*dto.LabelPair {
	labelPairs := make([]*dto.LabelPair, 0)
	for i, n := range sample.Labels {
		labelPairs = append(labelPairs, &dto.LabelPair{
			Name:  proto.String(i),
			Value: proto.String(n),
		})
	}
	return labelPairs
}
func (m *timeConstMetric) Desc() *prometheus.Desc {
	return m.desc
}
func (m *timeConstMetric) Write(out *dto.Metric) error {
	out.TimestampMs = &m.timestamp
	return populateMetric(m.valType, m.val, m.labelPairs, out)
}

func populateMetric(
	t prometheus.ValueType,
	v float64,
	labelPairs []*dto.LabelPair,
	m *dto.Metric,
) error {
	m.Label = labelPairs
	m.Gauge = &dto.Gauge{Value: proto.Float64(v)}
	return nil
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("netflow_exporter"))
		os.Exit(0)
	}

	log.Infoln("Starting netflow_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	http.Handle(*metricsPath, prometheus.Handler())

	c := newNetflowCollector()
	prometheus.MustRegister(c)

	udpAddress, err := net.ResolveUDPAddr("udp", *netflowAddress)
	if err != nil {
		log.Fatalf("Error resolving UDP address: %s", err)
	}
	udpSock, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		log.Fatalf("Error lisening to UDP address: %s", err)
	}
	go func() {
		defer udpSock.Close()
		decoders := make(map[string]*netflow.Decoder)
		for {
			buf := make([]byte, 65535)
			chars, srcAddress, err := udpSock.ReadFromUDP(buf)
			if err != nil {
				log.Errorf("Error reading UDP packet from %s: %s", srcAddress, err)
				continue
			}
			timestamp := int64(float64(time.Now().UnixNano()) / 1e9)
			d, found := decoders[srcAddress.String()]
			if !found {
				s := session.New()
				d = netflow.NewDecoder(s)
				decoders[srcAddress.String()] = d
			}
			m, err := d.Read(bytes.NewBuffer(buf[:chars]))
			if err != nil {
			}
			switch p := m.(type) {
			case *netflow5.Packet:
				netflow5.Dump(p)
			case *netflow9.Packet:
				netflow9.Dump(p)
				labels := prometheus.Labels{}
				counts := make(map[string]float64)
				for _, set := range p.DataFlowSets {
					for _, record := range set.Records {
						for _, field := range record.Fields {
							if regexp.MustCompile(`Count$`).MatchString(field.Translated.Name) {
								counts[field.Translated.Name] = float64(field.Translated.Value.(uint64))
							} else {
								labels[field.Translated.Name] = fmt.Sprintf("%v", field.Translated.Value)
							}
						}
						sample := netflowSample{
							Labels:      labels,
							Counts:      counts,
							TimestampMs: timestamp,
						}
						log.Infoln("send sample", sample)
						c.ch <- &sample
					}
				}
				//for key,value := range counts {
				//metric :=
				//}
				log.Infoln(labels, counts)
			}

		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
        <head><title>netflow Exporter</title></head>
        <body>
        <h1>netflow Exporter</h1>
        <p><a href='` + *metricsPath + `'>Metrics</a></p>
        </body>
        </html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
