#!/usr/bin/env ruby

require 'json'
require 'ipaddress'
require 'active_support/core_ext/hash'
require 'optparse'
require 'nokogiri'
require 'time'
require 'poseidon'
require 'getopt/std'
require_relative './rb_net_discovery'

module Redborder
  class HostDiscovery
    attr_reader :target, :scan_id, :subnets, :results, :ports

    def initialize(target:, scan_id:, kafka_broker:, enrichment: {}, ports: nil)
      @target = target
      @scan_id = scan_id
      @kafka_broker = kafka_broker
      @enrichment = enrichment.reject{ |key,value|
                      %w[service_provider_uuid service_provider
                         namespace namespace_uuid
                         organization organization_uuid
                         building building_uuid].include? key and value.empty?
                     } #if any of this fields is empty, remove it
      @ports = ports
      @subnets = []
      @results = {}
    end

    def discover
      puts "Initializing scanning for target: #{@target}"

      discover_subnets
      scan_subnets

      puts "\n[*] Scan completed!"
      puts "Hosts found: #{@results.values.flatten.size}"
    end

    private

    # Discovers subnets based on the target
    # Uses NetworkDiscovery to scan the target and find subnets
    def discover_subnets
      discovery = NetworkDiscovery.new(@target)
      @subnets = discovery.scan

      puts "\n[*] Discovered subnets:"
      @subnets.each { |s| puts "  - #{s}" }
    end

    # Scans each discovered subnet using Nmap
    def scan_subnets
      scan_time = Time.now.to_i

      @subnets.each do |subnet|
        puts "\n[*] Scanning subnet: #{subnet}..."

        output = nmap_query(subnet, @ports)
        if output.nil? || output.strip.empty?
          warn "Empty output for subnet: #{subnet}"
          next
        end

        hosts = extract_hosts_info(output, scan_time)
        @results[subnet] = hosts

        if hosts.any?
          puts "Found #{hosts.size} hosts in subnet #{subnet}:"
          hosts.each do |host|
            print_host(host)
            produce_to_kafka(host, @kafka_broker, @scan_id)
          end
        else
          puts "No hosts have been found in subnet #{subnet}."
        end
      end
    end

    # Extracts host information from the Nmap XML output
    # Returns an array of hashes with host details
    def extract_hosts_info(xml_output, timestamp)
      begin
        doc = Nokogiri::XML(xml_output) { |config| config.strict }
      rescue Nokogiri::XML::SyntaxError => e
        warn "[!] Invalid XML output: #{e.message}"
        return []
      end

      hosts = []

      doc.xpath('//host').each do |host_node|
        ip_node       = host_node.at_xpath('address[@addrtype="ipv4"]')
        mac_node      = host_node.at_xpath('address[@addrtype="mac"]')
        hostname_node = host_node.at_xpath('hostnames/hostname')
        os_node       = host_node.at_xpath('os/osmatch')
        osclass_node  = os_node&.at_xpath('osclass')

        ports    = []
        tcp_ports = []
        udp_ports = []
        services  = []
        cpes      = []

        host_node.xpath('ports/port[state/@state="open"]').each do |port_node|
          portid   = port_node['portid']
          protocol = port_node['protocol']
          service  = port_node.at_xpath('service')

          ports     << portid
          services  << service['name'] if service&.[]('name')
          cpes     += port_node.xpath('service/cpe').map(&:text)

          tcp_ports << portid if protocol == 'tcp'
          udp_ports << portid if protocol == 'udp'
        end

        host = {
          "ip"              => ip_node&.[]('addr'),
          "mac"             => mac_node&.[]('addr'),
          "vendor"          => mac_node&.[]('vendor'),
          "hostname"        => hostname_node&.[]('name'),
          "os"              => os_node&.[]('name'),
          "os_vendor"       => osclass_node&.[]('vendor'),
          "os_family"       => osclass_node&.[]('osfamily'),
          "os_gen"          => osclass_node&.[]('osgen'),
          "services"        => services.uniq.join(','),
          "cpe"             => cpes.uniq.join(','),
          "open_ports_count"=> ports.uniq.size,
          "scan_id"         => @scan_id,
          "timestamp"       => timestamp
        }

        hosts << host if host["ip"]
      end

      hosts
    end

    # Produces host information to Kafka
    def produce_to_kafka(host, kafka_broker, scan_id, topic = "rb_host_discovery")
      return unless host["ip"]

      # Renanme enrichment keys
      enrichment_renamed = @enrichment.dup
      enrichment_renamed["sensor_name"] = enrichment_renamed.delete("name") if enrichment_renamed.key?("name")
      enrichment_renamed["sensor_uuid"] = enrichment_renamed.delete("uuid") if enrichment_renamed.key?("uuid")

      payload = {
        "scan_id"   => scan_id,
        "scan_type" => "2"
      }.merge(host).merge(enrichment_renamed)

      kafka_id = "rb_host_discovery_producer"

      begin
        kafka_producer = Poseidon::Producer.new([kafka_broker], kafka_id)
        message = Poseidon::MessageToSend.new(topic, payload.to_json)
        kafka_producer.send_messages([message])

        puts "Host details #{payload.inspect}"
      rescue => e
        warn "  [!] Error sending to kafka (#{topic}): #{e.message}"
      end
    end


    def print_host(host)
      puts "    - #{host['ip']}#{host['hostname'] ? " (#{host['hostname']})" : ''}"
    end

    # Runs an Nmap query on the given subnet
    def nmap_query(subnet, ports)
      ports = ports.to_s.delete(' ')
      ports = "all" if ports.empty?
      is_port_all = ports.casecmp("all").zero?

      # valida números, comas y guiones; si no, ignora -p
      unless is_port_all || ports.match?(/\A[0-9,\-]+\z/)
        warn "Invalid ports: #{ports}"
        is_port_all = true
      end

      command = "nmap -O -T4"
      command << " -p #{ports}" unless is_port_all
      command << " #{subnet} -oX -"

      puts "Running command: #{command}"
      output = `#{command}`
      if $?.exitstatus != 0
        warn "Nmap command failed with exit status: #{$?.exitstatus}"
        return nil
      end
      output
    rescue => e
      warn "Error running nmap query: #{e.message}"
      nil
    end
  end
end

opt = Getopt::Std.getopts("t:p:s:e:b:k:d")

unless opt["t"] && opt["s"]
  puts "ERROR: Debes indicar un target (-t) y un scan_id (-s)"
  exit 1
end

target       = opt["t"]
ports        = opt["p"] || "all"
scan_id      = opt["s"]
kafka_broker = opt["k"] || "kafka.service:9092"
debug        = opt["d"] || false
enrichment   = JSON.parse(opt["e"]) rescue {}

discovery = Redborder::HostDiscovery.new(
  target: target,
  scan_id: scan_id,
  kafka_broker: kafka_broker,
  ports: ports,
  enrichment: enrichment
)

discovery.discover
