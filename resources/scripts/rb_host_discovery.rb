#!/usr/bin/env ruby

require 'json'
require 'ipaddress'
require 'active_support/core_ext/hash'
require 'optparse'
require 'nokogiri'
require 'time'
require 'poseidon'
require 'getopt/std'
require 'open3'
require 'timeout'
require_relative './rb_net_discovery'

module Redborder
  class HostDiscovery
    attr_reader :target, :scan_id, :subnets, :results, :ports

    # Skip subnets larger than this (e.g. a /16 mis-inferred from a route table)
    # to avoid multi-hour, network-wide nmap sweeps.
    MAX_SUBNET_HOSTS = 1024 # roughly a /22

    # Kill a per-subnet nmap scan that runs longer than this so one
    # unresponsive/filtered subnet can't wedge the whole scan job.
    NMAP_TIMEOUT_SECONDS = 300

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
      @kafka_producer = nil
      @published_ips = {}
    end

    def discover
      puts "Initializing scanning for target: #{@target}"

      @kafka_producer = create_kafka_producer

      discover_subnets
      scan_subnets

      puts "\n[*] Scan completed!"
      puts "Hosts found: #{@results.values.flatten.size}"
    end

    private

    # Creates a single Kafka producer reused for the whole scan run instead
    # of opening a new connection per discovered host.
    def create_kafka_producer
      Poseidon::Producer.new([@kafka_broker], "rb_host_discovery_producer")
    rescue => e
      warn "  [!] Error creating kafka producer: #{e.message}"
      nil
    end

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
        if subnet_too_large?(subnet)
          warn "Skipping subnet #{subnet}: exceeds max scannable size (#{MAX_SUBNET_HOSTS} hosts)"
          next
        end

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

            # The same host can appear under more than one discovered
            # subnet when subnets overlap; only publish it once per scan.
            if host["ip"] && @published_ips[host["ip"]]
              puts "    (already reported in subnet #{@published_ips[host["ip"]]}, skipping duplicate)"
              next
            end

            produce_to_kafka(host, @scan_id)
            @published_ips[host["ip"]] = subnet if host["ip"]
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
          "services"        => services.uniq,
          "cpe"             => cpes.uniq,
          "open_ports_count"=> ports.uniq.size,
          "scan_id"         => @scan_id,
          "timestamp"       => timestamp
        }

        hosts << host if host["ip"]
      end

      hosts
    end

    # Produces host information to Kafka using the producer created once
    # per scan run in #discover.
    def produce_to_kafka(host, scan_id, topic = "rb_host_discovery")
      return unless host["ip"]

      unless @kafka_producer
        warn "  [!] Skipping kafka publish for #{host["ip"]}: no producer available"
        return
      end

      # Renanme enrichment keys
      enrichment_renamed = @enrichment.dup
      enrichment_renamed["sensor_name"] = enrichment_renamed.delete("name") if enrichment_renamed.key?("name")
      enrichment_renamed["sensor_uuid"] = enrichment_renamed.delete("uuid") if enrichment_renamed.key?("uuid")

      payload = {
        "scan_id"   => scan_id,
        "scan_type" => "2"
      }.merge(host).merge(enrichment_renamed)

      begin
        # Keyed by scan_id so all hosts from the same scan land on the same
        # partition, giving consumers a per-scan ordering guarantee.
        message = Poseidon::MessageToSend.new(topic, payload.to_json, scan_id.to_s)
        @kafka_producer.send_messages([message])

        puts "Host details #{payload.inspect}"
      rescue => e
        warn "  [!] Error sending to kafka (#{topic}): #{e.message}"
      end
    end

    # True if the subnet contains more addresses than we're willing to
    # sweep with a full nmap -O scan in one job.
    def subnet_too_large?(subnet)
      IPAddress(subnet).size > MAX_SUBNET_HOSTS
    rescue
      false
    end


    def print_host(host)
      puts "    - #{host['ip']}#{host['hostname'] ? " (#{host['hostname']})" : ''}"
    end

    # Runs an Nmap query on the given subnet, killing it if it runs past
    # NMAP_TIMEOUT_SECONDS so a single filtered/unresponsive subnet can't
    # block the rest of the scan job.
    def nmap_query(subnet, ports)
      ports = ports.to_s.delete(' ')
      ports = "all" if ports.empty?
      is_port_all = ports.casecmp("all").zero?

      # valida números, comas y guiones; si no, ignora -p
      unless is_port_all || ports.match?(/\A[0-9,\-]+\z/)
        warn "Invalid ports: #{ports}"
        is_port_all = true
      end

      command = ["nmap", "-O", "-T4"]
      command += ["-p", ports] unless is_port_all
      command += [subnet, "-oX", "-"]

      puts "Running command: #{command.join(' ')}"
      run_with_timeout(command, NMAP_TIMEOUT_SECONDS)
    rescue => e
      warn "Error running nmap query: #{e.message}"
      nil
    end

    # Runs an external command (argv array, no shell) and returns its
    # stdout, or nil on non-zero exit / timeout. On timeout, the process
    # (and its children) is sent TERM then KILL rather than left running.
    def run_with_timeout(cmd_array, timeout_seconds)
      Open3.popen3(*cmd_array) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        # Drain stdout/stderr concurrently: reading them sequentially can
        # deadlock if both pipe buffers fill at once (large -oX output).
        out = nil
        err = nil
        out_reader = Thread.new { out = stdout.read }
        err_reader = Thread.new { err = stderr.read }

        begin
          Timeout.timeout(timeout_seconds) do
            out_reader.join
            err_reader.join
            status = wait_thr.value
            unless status.success?
              warn "Nmap command failed with exit status: #{status.exitstatus}. #{err}"
              return nil
            end
            return out
          end
        rescue Timeout::Error
          warn "Nmap command timed out after #{timeout_seconds}s, killing pid #{wait_thr.pid}"
          out_reader.kill
          err_reader.kill
          kill_and_reap(wait_thr)
          return nil
        end
      end
    end

    # Terminates a timed-out child, escalating to KILL if it ignores TERM,
    # and reaps it via the Open3 wait thread (rather than Process.wait
    # directly, which would race with wait_thr's own reap and can raise
    # Errno::ECHILD).
    def kill_and_reap(wait_thr)
      pid = wait_thr.pid
      Process.kill("TERM", pid)
      unless wait_thr.join(2)
        warn "  [!] nmap pid #{pid} did not exit after TERM, sending KILL"
        Process.kill("KILL", pid)
        wait_thr.join
      end
    rescue Errno::ESRCH
      # already exited
    rescue => e
      warn "  [!] Error killing timed-out nmap process #{pid}: #{e.message}"
    end
  end
end

opt = Getopt::Std.getopts("t:p:s:e:k:d")

unless opt["t"] && opt["s"]
  puts 'ERROR: You must specify a target (-t) and a scan_id (-s)'
  exit 1
end

target       = opt["t"]
ports        = opt["p"] || "all"
scan_id      = opt["s"]
kafka_broker = opt["k"] || "kafka.service:9092"
debug        = opt["d"] || false

enrichment =
  if opt["e"].nil? || opt["e"].empty?
    {}
  else
    begin
      parsed = JSON.parse(opt["e"])
      unless parsed.is_a?(Hash)
        warn "  [!] Enrichment JSON (-e) must be an object, got #{parsed.class}. Continuing with empty enrichment."
        parsed = {}
      end
      parsed
    rescue JSON::ParserError => e
      warn "  [!] Invalid enrichment JSON (-e): #{e.message}. Continuing with empty enrichment."
      {}
    end
  end

discovery = Redborder::HostDiscovery.new(
  target: target,
  scan_id: scan_id,
  kafka_broker: kafka_broker,
  ports: ports,
  enrichment: enrichment
)

discovery.discover
