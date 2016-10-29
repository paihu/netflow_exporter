package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
    "strings"
	"sync"
	"time"

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
	showVersion     = flag.Bool("version", false, "Print version information.")
	netflowAddress  = flag.String("netflow.listen-address", ":2055", "Network address on which to accept netflow binary network packets, e.g. \":2055\".")
	listenAddress   = flag.String("web.listen-address", ":9191", "Address on which to expose metrics.")
	metricsPath     = flag.String("web.telemetry-path", "/metrics", "Path under which to expose Prometheus metrics.")
	netflowCollects = flag.String("netflow.collect", "Count$", "Regexp match type is Collect metrics.")
	netflowExclude  = flag.String("netflow.exclude", "Time", "Regexp match type is not use Label.")
	sampleExpiry    = flag.Duration("netflow.sample-expiry", 5*time.Minute, "How long a sample is valid for.")
	lastProcessed   = prometheus.NewGauge(
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

func (c *netflowCollector) processReader(udpSock *net.UDPConn) {
	defer udpSock.Close()
	decoders := make(map[string]*netflow.Decoder)
	for {
		buf := make([]byte, 65535)
		chars, srcAddress, err := udpSock.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("Error reading UDP packet from %s: %s", srcAddress, err)
			continue
		}
		timestampMs := int64(float64(time.Now().UnixNano()) / 1e6)
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

			for _, record := range p.Records {
				labels := prometheus.Labels{}
				counts := make(map[string]float64)
				labels["sourceIPv4Address"] = record.SrcAddr.String()
				labels["destinationIPv4Address"] = record.DstAddr.String()
				labels["sourceTransportPort"] = strconv.FormatUint(uint64(record.SrcPort), 10)
				labels["destinationTransportPort"] = strconv.FormatUint(uint64(record.DstPort), 10)
				counts["packetDeltaCount"] = float64(record.Packets)
				counts["octetDeltaCount"] = float64(record.Bytes)
				labels["protocolIdentifier"] = strconv.FormatUint(uint64(record.Protocol), 10)
				labels["tcpControlBits"] = strconv.FormatUint(uint64(record.TCPFlags), 10)
				labels["bgpSourceAsNumber"] = strconv.FormatUint(uint64(record.SrcAS), 10)
				labels["bgpDestinationAsNumber"] = strconv.FormatUint(uint64(record.DstAS), 10)
				labels["sourceIPv4PrefixLength"] = strconv.FormatUint(uint64(record.SrcMask), 10)
				labels["destinationIPv4PrefixLength"] = strconv.FormatUint(uint64(record.DstMask), 10)
				if (len(counts) > 0) && (len(labels) > 0) {
					labels["From"] = srcAddress.IP.String()
					labels["NetflowVersion"] = "5"

					sample := &netflowSample{
						Labels:      labels,
						Counts:      counts,
						TimestampMs: timestampMs,
					}
					lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
					c.ch <- sample
				}
			}

		case *netflow9.Packet:
			for _, set := range p.DataFlowSets {
				for _, record := range set.Records {
					labels := prometheus.Labels{}
					counts := make(map[string]float64)
					for _, field := range record.Fields {
						if len(*netflowExclude) > 0 && regexp.MustCompile(*netflowExclude).MatchString(field.Translated.Name) {
							//log.Infoln(field,"is not using label")
						} else if regexp.MustCompile(*netflowCollects).MatchString(field.Translated.Name) {
							counts[field.Translated.Name] = float64(field.Translated.Value.(uint64))
							//log.Infoln(field,"is using metric")
						} else {
							labels[field.Translated.Name] = fmt.Sprintf("%v", field.Translated.Value)
						}

					}
					if (len(counts) > 0) && (len(labels) > 0) {
						labels["From"] = srcAddress.IP.String()
						labels["TemplateID"] = fmt.Sprintf("%d",record.TemplateID)
						labels["NetflowVersion"] = "9"

						sample := &netflowSample{
							Labels:      labels,
							Counts:      counts,
							TimestampMs: timestampMs,
						}
						lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
						c.ch <- sample
					}
				}
			}
		default:
			log.Infoln("packet is not supported version")
		}

	}
}

func makeEntryName(l map[string]string) string {
	keys := []string{}
	for key, _ := range l {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var name string
	for _, key := range keys {
		name += key + "=" + l[key]
	}
	return name
}
func (c *netflowCollector) processSamples() {
	ticker := time.NewTicker(time.Minute).C
	for {
		select {
		case sample := <-c.ch:

			c.mu.Lock()

			_, ok := c.samples[makeEntryName(sample.Labels)]

			if !ok || (c.samples[makeEntryName(sample.Labels)].TimestampMs < sample.TimestampMs) {
				c.samples[makeEntryName(sample.Labels)] = sample
			}
			c.mu.Unlock()
		case <-ticker:
			ageLimit := int64(float64(time.Now().Add(-*sampleExpiry).UnixNano()) / 1e6)
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
	ageLimit := int64(float64(time.Now().Add(-*sampleExpiry).UnixNano()) / 1e6)
	for _, sample := range samples {
		if ageLimit >= sample.TimestampMs {
			continue
		}
		for key, value := range sample.Counts {
            desc :=""
			if sample.Labels["TemplateID"] != "" {
				desc = fmt.Sprintf("netflow_%s_TemplateID%s_%s", sample.Labels["From"], sample.Labels["TemplateID"], key)
			} else {
				desc = fmt.Sprintf("netflow_%s_%s", sample.Labels["From"], key)
			}
            desc = strings.Replace(desc,".","",-1)
            log.Infoln(desc)
			ch <- MustNewTimeConstMetric(
				prometheus.NewDesc(desc,
					fmt.Sprintf("netflow metric %s", key),
					[]string{}, sample.Labels),
				prometheus.GaugeValue, value, sample.TimestampMs)
		}
	}
}

func NewTimeConstMetric(desc *prometheus.Desc, valueType prometheus.ValueType,
	value float64, timestampMs int64) (prometheus.Metric, error) {
	return &timeConstMetric{
		timestampMs: timestampMs,
		metric:      prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, []string{}...),
	}, nil
}
func MustNewTimeConstMetric(desc *prometheus.Desc, valueType prometheus.ValueType,
	value float64, timestampMs int64) prometheus.Metric {
	m, err := NewTimeConstMetric(desc, valueType, value, timestampMs)
	if err != nil {
		panic(err)
	}

	return m
}

type timeConstMetric struct {
	timestampMs int64
	metric      prometheus.Metric
}

func (m *timeConstMetric) Desc() *prometheus.Desc {
	return m.metric.Desc()
}
func (m *timeConstMetric) Write(out *dto.Metric) error {
	out.TimestampMs = &m.timestampMs
	return m.metric.Write(out)
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
	log.Infoln("include", *netflowCollects)
	if len(*netflowExclude) > 0 {
		log.Infoln("exclude", *netflowExclude)
	}
	go c.processReader(udpSock)

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
	log.Infoln("Listening UDP on", *netflowAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
