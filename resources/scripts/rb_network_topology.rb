#!/usr/bin/env ruby
require 'ipaddr'
require 'json'
require 'open3'
require 'optparse'
require 'rexml/document'
require 'securerandom'
require 'time'
require 'timeout'

module Redborder
  class NetworkTopology
    MAX_HOSTS = 1024
    MAX_BYTES = 750_000

    def initialize(target)
      unless target.to_s.match?(/\A\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\z/)
        raise ArgumentError, 'Target must be one IPv4 address or CIDR'
      end
      @network = IPAddr.new(target)
      raise ArgumentError, 'IPv4 required' unless @network.ipv4?
      size = @network.to_range.last.to_i - @network.to_range.first.to_i + 1
      raise ArgumentError, "Target exceeds #{MAX_HOSTS} addresses" if size > MAX_HOSTS
      @target = target
    end

    def command
      ['/usr/bin/nmap', '-sn', '--traceroute', '-n', '--max-retries', '2',
       '--host-timeout', '30s', '-oX', '-', @target]
    end

    def scan
      output = nil
      Open3.popen3(*command) do |input, stdout, stderr, waiter|
        input.close
        errors = Thread.new { stderr.read }
        begin
          Timeout.timeout(300) do
            output = stdout.read
            raise "Nmap failed: #{errors.value}" unless waiter.value.success?
          end
        rescue Timeout::Error
          Process.kill('KILL', waiter.pid) rescue Errno::ESRCH
          raise 'Topology scan exceeded 300 seconds'
        ensure
          errors.join
        end
      end
      parse(output)
    end

    def parse(xml)
      xml = xml.sub('<!DOCTYPE nmaprun>', '')
      raise ArgumentError, 'XML document types are not accepted' if xml.include?('<!DOCTYPE')
      document = REXML::Document.new(xml)
      unless document.elements['nmaprun/runstats/finished']&.attributes&.[]('exit') == 'success'
        raise 'Nmap did not complete successfully'
      end
      nodes, links = {}, {}
      document.elements.each('nmaprun/host') do |host|
        next unless host.elements['status']&.attributes&.[]('state') == 'up'
        address = host.elements['address[@addrtype="ipv4"]']&.attributes&.[]('addr')
        next unless address && @network.include?(IPAddr.new(address))
        nodes[address] = node(address, 'host').merge(
          'hostname' => host.elements['hostnames/hostname']&.attributes&.[]('name').to_s,
          'mac' => host.elements['address[@addrtype="mac"]']&.attributes&.[]('addr').to_s,
          'vendor' => host.elements['address[@addrtype="mac"]']&.attributes&.[]('vendor').to_s
        )
        add_trace(host, nodes, links)
      end
      { 'schema_version' => 1, 'target' => @target,
        'nodes' => nodes.values, 'links' => links.values }
    end

    def event(snapshot, scan_id, enrichment)
      topology_json = JSON.generate(snapshot)
      raise 'Topology snapshot exceeds size limit' if topology_json.bytesize > MAX_BYTES
      metadata = enrichment.dup
      metadata['sensor_name'] = metadata.delete('name') if metadata.key?('name')
      metadata['sensor_uuid'] = metadata.delete('uuid') if metadata.key?('uuid')
      completed = Time.now.utc
      metadata.merge('scan_id' => scan_id.to_s, 'scan_type' => 'network_topology',
                     'schema_version' => 1, 'snapshot_id' => SecureRandom.uuid,
                     'timestamp' => completed.to_i, 'completed_at' => completed.iso8601(6),
                     'topology_json' => topology_json)
    end

    private

    def node(address, kind)
      ip = IPAddr.new(address)
      raise ArgumentError, 'Invalid IPv4 hop' unless ip.ipv4? && ip.to_s == address
      { 'ip' => address, 'kind' => kind,
        'subnet' => @network.include?(ip) ? @target : 'Transit hops' }
    end

    def add_trace(host, nodes, links)
      previous = nil
      host.elements.each('trace/hop') do |hop|
        address = hop.attributes['ipaddr']
        ttl = hop.attributes['ttl'].to_i
        unless address && ttl.positive?
          previous = nil
          next
        end
        nodes[address] ||= node(address, 'hop')
        if previous && ttl == previous[:ttl] + 1 && address != previous[:ip]
          key = [previous[:ip], address]
          links[key] = { 'source' => previous[:ip], 'target' => address,
                         'evidence' => 'traceroute' }
        end
        previous = { ip: address, ttl: ttl }
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = { kafka: 'kafka.service:9092', enrichment: '{}' }
  OptionParser.new do |parser|
    parser.on('-t TARGET') { |value| options[:target] = value }
    parser.on('-s SCAN_ID') { |value| options[:scan_id] = value }
    parser.on('-k BROKER') { |value| options[:kafka] = value }
    parser.on('-e JSON') { |value| options[:enrichment] = value }
    parser.on('-p PORTS') { |_| }
    parser.on('-d') { }
  end.parse!
  begin
    raise ArgumentError, 'Target and scan ID are required' unless options[:target] && options[:scan_id]
    enrichment = JSON.parse(options[:enrichment])
    raise ArgumentError, 'Sensor UUID is required' if enrichment['uuid'].to_s.empty?
    scanner = Redborder::NetworkTopology.new(options[:target])
    payload = scanner.event(scanner.scan, options[:scan_id], enrichment)
    encoded = JSON.generate(payload)
    raise 'Encoded topology event exceeds 900,000 bytes' if encoded.bytesize > 900_000
    require 'poseidon'
    producer = Poseidon::Producer.new([options[:kafka]], 'rb_network_topology', required_acks: 1)
    producer.send_messages([Poseidon::MessageToSend.new('rb_network_topology', encoded)])
  rescue StandardError => e
    warn "Topology discovery failed: #{e.message}"
    exit 1
  ensure
    producer.close if producer
  end
end
