#!/usr/bin/env ruby

require 'json'
require 'shellwords'
require 'ipaddress'
require 'nokogiri'
require 'time'
require 'poseidon'
require 'getopt/std'

# Discovers network topology from the sensor point of view and sends it to Kafka.
#
# L3: nmap ping sweep finds live hosts, traceroute gives the router path to each one.
# L2: the local ARP table (ip neigh) and bridge FDB give host <-> interface/port links.
#
# Two kinds of records are produced to the topic (field "record_type"):
#   node: ip, mac, hostname, vendor, role (sensor|router|host)
#   link: from_ip, to_ip, layer (l2|l3), source (traceroute|arp|fdb), interface/mac when known
module Redborder
  class TopologyDiscovery
    TOPIC = "rb_topology_discovery"
    MAX_HOPS = 20
    THREADS = 8

    attr_reader :nodes, :links

    def initialize(target:, scan_id:, kafka_broker:, enrichment: {}, debug: false)
      @target = target
      @scan_id = scan_id
      @kafka_broker = kafka_broker
      @debug = debug
      @enrichment = enrichment.reject { |key, value|
                      %w[service_provider_uuid service_provider
                         namespace namespace_uuid
                         organization organization_uuid
                         building building_uuid].include? key and value.empty?
                    }
      @nodes = {}   # ip => node hash
      @links = {}   # [from_ip, to_ip, layer] => link hash
      @mutex = Mutex.new
    end

    def discover
      puts "Initializing topology discovery for target: #{@target}"
      @scan_time = Time.now.to_i

      add_sensor_node
      live_hosts = ping_sweep
      puts "[*] Live hosts: #{live_hosts.size}"

      read_arp_table
      read_bridge_fdb
      trace_hosts(live_hosts.map { |h| h["ip"] })

      puts "[*] Nodes: #{@nodes.size}, links: #{@links.size}"
      send_to_kafka
    end

    private

    def valid_target?
      IPAddress(@target)
      true
    rescue ArgumentError
      false
    end

    def local_ip
      @local_ip ||= begin
        out = `ip -4 route get #{@target.split('/').first} 2>/dev/null`
        out[/src (\d+\.\d+\.\d+\.\d+)/, 1]
      end
    end

    def add_sensor_node
      ip = local_ip
      return puts("[!] Could not determine the local IP of the sensor") unless ip

      add_node(ip, role: "sensor", hostname: `hostname`.strip)
    end

    # ARP/ICMP sweep. Returns [{ "ip", "mac", "vendor", "hostname" }]
    def ping_sweep
      unless valid_target?
        warn "[!] Invalid target: #{@target}"
        return []
      end

      output = `nmap -sn -T4 #{@target.shellescape} -oX - 2>/dev/null`
      return [] if output.to_s.strip.empty?

      doc = Nokogiri::XML(output)
      doc.xpath('//host[status/@state="up"]').map do |host|
        ip = host.at_xpath('address[@addrtype="ipv4"]')&.[]('addr')
        next unless ip

        mac = host.at_xpath('address[@addrtype="mac"]')
        node = { "ip" => ip,
                 "mac" => mac&.[]('addr'),
                 "vendor" => mac&.[]('vendor'),
                 "hostname" => host.at_xpath('hostnames/hostname')&.[]('name') }
        add_node(ip, role: "host", mac: node["mac"], vendor: node["vendor"], hostname: node["hostname"])
        node
      end.compact
    end

    # `ip neigh`: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    def read_arp_table
      `ip -4 neigh show 2>/dev/null`.each_line do |line|
        ip, iface, mac = line.match(/\A(\S+) dev (\S+) lladdr (\S+)/)&.captures
        next unless ip && local_ip

        add_node(ip, mac: mac)
        add_link(local_ip, ip, "l2", "arp", interface: iface, to_mac: mac)
      end
    end

    # `bridge fdb show`: "aa:bb:cc:dd:ee:ff dev eth1 master br0" (only when the sensor has bridges)
    def read_bridge_fdb
      out = `bridge fdb show 2>/dev/null`
      return if out.to_s.empty?

      out.each_line do |line|
        mac, iface = line.match(/\A([0-9a-f:]{17}) dev (\S+)/i)&.captures
        next unless mac && local_ip
        next if line.include?("permanent") || line.include?("self")

        ip = @mutex.synchronize { @nodes.values.find { |n| n["mac"]&.casecmp?(mac) }&.[]("ip") }
        add_link(local_ip, ip, "l2", "fdb", interface: iface, to_mac: mac) if ip
      end
    end

    def trace_hosts(ips)
      queue = Queue.new
      ips.each { |ip| queue << ip }
      workers = Array.new(THREADS) do
        Thread.new do
          loop do
            ip = begin
              queue.pop(true)
            rescue ThreadError
              break
            end
            trace(ip)
          end
        end
      end
      workers.each(&:join)
    end

    # Adds a link between each consecutive pair of responding hops.
    # Hops that did not answer ("* * *") break the chain, we do not invent links across them.
    def trace(ip)
      out = `traceroute -n -q 1 -w 1 -m #{MAX_HOPS} #{ip.shellescape} 2>/dev/null`
      previous = local_ip
      out.each_line.drop(1).each do |line|
        hop_ip = line.match(/\A\s*\d+\s+(\d+\.\d+\.\d+\.\d+)/)&.captures&.first
        if hop_ip.nil?
          previous = nil
          next
        end

        add_node(hop_ip, role: hop_ip == ip ? "host" : "router")
        add_link(previous, hop_ip, "l3", "traceroute") if previous && previous != hop_ip
        previous = hop_ip
      end
      puts "  traced #{ip}" if @debug
    end

    def add_node(ip, role: nil, mac: nil, vendor: nil, hostname: nil)
      @mutex.synchronize do
        node = (@nodes[ip] ||= { "ip" => ip })
        node["role"] = role if role && (node["role"].nil? || node["role"] == "host")
        node["mac"] ||= mac if mac
        node["vendor"] ||= vendor if vendor
        node["hostname"] ||= hostname if hostname && !hostname.empty?
      end
    end

    def add_link(from_ip, to_ip, layer, source, interface: nil, to_mac: nil)
      return if from_ip.nil? || to_ip.nil?

      key = [from_ip, to_ip, layer]
      @mutex.synchronize do
        @links[key] ||= { "from_ip" => from_ip, "to_ip" => to_ip, "layer" => layer,
                          "source" => source, "interface" => interface, "to_mac" => to_mac }.compact
      end
    end

    def send_to_kafka
      enrichment = @enrichment.dup
      enrichment["sensor_name"] = enrichment.delete("name") if enrichment.key?("name")
      enrichment["sensor_uuid"] = enrichment.delete("uuid") if enrichment.key?("uuid")

      base = { "scan_id" => @scan_id, "scan_type" => "3", "timestamp" => @scan_time }.merge(enrichment)
      records = @nodes.values.map { |n| base.merge("record_type" => "node").merge(n) } +
                @links.values.map { |l| base.merge("record_type" => "link").merge(l) }

      producer = Poseidon::Producer.new([@kafka_broker], "rb_topology_discovery_producer")
      records.each_slice(100) do |slice|
        producer.send_messages(slice.map { |r| Poseidon::MessageToSend.new(TOPIC, r.to_json) })
      end
      producer.close
      puts "[*] Sent #{records.size} records to #{TOPIC}"
    rescue => e
      warn "[!] Error sending to kafka (#{TOPIC}): #{e.message}"
    end
  end
end

opt = Getopt::Std.getopts("t:p:s:e:b:k:d")

unless opt["t"] && opt["s"]
  puts 'ERROR: You must specify a target (-t) and a scan_id (-s)'
  exit 1
end

Redborder::TopologyDiscovery.new(
  target: opt["t"],
  scan_id: opt["s"],
  kafka_broker: opt["k"] || "kafka.service:9092",
  enrichment: (JSON.parse(opt["e"]) rescue {}),
  debug: opt["d"] || false
).discover
