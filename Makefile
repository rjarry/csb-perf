# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Robin Jarry

.PHONY: install
install:
	dnf install -y grafana prometheus bpftrace python3
	install -Dm644 logrotate.d/osquery-trace /etc/logrotate.d/osquery-trace
	install -Dm644 -t /etc/prometheus prometheus/bpfstats.py
	install -Dm644 -t /etc/prometheus prometheus/file-trace.bt
	install -Dm644 -t /etc/prometheus prometheus/prometheus.yml
	install -Dm755 -t /etc/prometheus prometheus/compile-ab.py
	install -Dm755 -t /etc/prometheus prometheus/idle-ab.py
	install -Dm755 -t /etc/prometheus prometheus/power-exporter.py
	install -Dm644 -t /etc/grafana/dashboards/ grafana/dashboards/*.json
	install -Dm644 -t /etc/grafana/provisioning/dashboards/ grafana/provisioning/dashboards/*.yaml
	install -Dm644 -t /etc/grafana/provisioning/datasources/ grafana/provisioning/datasources/*.yaml
	install -Dm644 -t /etc/systemd/system/ systemd/*
	systemctl daemon-reload
	systemctl enable --now prometheus.service grafana-server.service \
		power-exporter.service osquery-trace.service
