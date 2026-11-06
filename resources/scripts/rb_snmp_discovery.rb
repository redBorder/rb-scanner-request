#!/usr/bin/env ruby

require 'open3'
require 'tmpdir'
require 'fileutils'

# Reads LLDP / CDP neighbors and interface names from network devices over SNMP.
#
# Credentials come from the environment (RB_SNMP_*), never from the command line, and are given
# to net-snmp through a 0600 snmp.conf in a private temp dir, so they do not show up in `ps`.
module Redborder
  class SnmpDiscovery
    OID_SYS_DESCR          = '1.3.6.1.2.1.1.1.0'
    OID_SYS_NAME           = '1.3.6.1.2.1.1.5.0'
    OID_IF_NAME            = '1.3.6.1.2.1.31.1.1.1.1'
    OID_LLDP_LOC_PORT_DESC = '1.0.8802.1.1.2.1.3.7.1.4'
    OID_LLDP_REM           = '1.0.8802.1.1.2.1.4.1.1'
    OID_LLDP_REM_MAN_ADDR  = '1.0.8802.1.1.2.1.4.2.1.3'
    OID_CDP_CACHE          = '1.3.6.1.4.1.9.9.23.1.2.1.1'

    VERSIONS = %w[1 2c 3].freeze

    # Builds a client from RB_SNMP_* variables, or returns nil when SNMP is not configured
    def self.from_env(env = ENV)
      version = env['RB_SNMP_VERSION'].to_s.downcase.delete('v')
      return nil unless VERSIONS.include?(version)
      return nil if version != '3' && env['RB_SNMP_COMMUNITY'].to_s.empty?
      return nil if version == '3' && env['RB_SNMP_USERNAME'].to_s.empty?

      new(version: version,
          community: env['RB_SNMP_COMMUNITY'],
          security_level: env['RB_SNMP_SECURITY_LEVEL'],
          username: env['RB_SNMP_USERNAME'],
          auth_protocol: env['RB_SNMP_AUTH_PROTOCOL'], auth_password: env['RB_SNMP_AUTH_PASSWORD'],
          priv_protocol: env['RB_SNMP_PRIV_PROTOCOL'], priv_password: env['RB_SNMP_PRIV_PASSWORD'])
    end

    # "C0 A8 01 01" -> "192.168.1.1" (only 4 octet values)
    def self.hex_to_ip(value)
      octets = value.to_s.split(/[\s:]+/)
      return nil unless octets.size == 4 && octets.all? { |o| o =~ /\A\h{1,2}\z/ }

      octets.map { |o| o.to_i(16) }.join('.')
    end

    # "AA BB CC DD EE FF" or "aa:bb:cc:dd:ee:ff" -> "aa:bb:cc:dd:ee:ff"
    def self.to_mac(value)
      octets = value.to_s.split(/[\s:]+/)
      return nil unless octets.size == 6 && octets.all? { |o| o =~ /\A\h{1,2}\z/ }

      octets.map { |o| o.rjust(2, '0').downcase }.join(':')
    end

    # Output of `snmpwalk -Oqn` -> [[oid, value], ...]
    def self.parse_walk(output)
      output.to_s.each_line.map do |line|
        match = line.chomp.match(/\A\.?(\d[\d.]*)\s+(.*)\z/)
        next unless match

        [match[1], match[2].strip.delete_prefix('"').delete_suffix('"')]
      end.compact
    end

    # runner: optional lambda(ip, oid) -> raw walk output, used by the tests
    def initialize(config, runner: nil, timeout: 2)
      @config = config
      @runner = runner
      @timeout = timeout
      @conf_dir = nil
    end

    def close
      FileUtils.remove_entry(@conf_dir) if @conf_dir && File.directory?(@conf_dir)
      @conf_dir = nil
    end

    # Returns { sys_name:, sys_descr:, neighbors: [...] } or nil if the device does not answer
    def query(ip)
      sys_name = walk(ip, OID_SYS_NAME).first&.last
      return nil if sys_name.nil? || sys_name.empty?

      if_names = walk(ip, OID_IF_NAME).map { |oid, v| [oid.split('.').last, v] }.to_h
      lldp_ports = walk(ip, OID_LLDP_LOC_PORT_DESC).map { |oid, v| [oid.split('.').last, v] }.to_h
      port_name = ->(index) { if_names[index] || lldp_ports[index] || "port #{index}" }

      { sys_name: sys_name,
        sys_descr: walk(ip, OID_SYS_DESCR).first&.last,
        neighbors: lldp_neighbors(ip, port_name) + cdp_neighbors(ip, port_name) }
    end

    # Breadth-first crawl over the neighbors, limited by depth, scope and a deadline.
    # Returns [{ ip:, sys_name:, sys_descr:, neighbors: }]
    def crawl(seeds, in_scope:, max_depth: 3, deadline: nil)
      visited = {}
      queue = seeds.map { |ip| [ip, 0] }
      devices = []

      until queue.empty?
        break if deadline && Time.now > deadline

        ip, depth = queue.shift
        next if visited[ip]

        visited[ip] = true
        info = query(ip)
        next unless info

        devices << info.merge(ip: ip)
        next if depth >= max_depth

        info[:neighbors].each do |n|
          queue << [n[:remote_ip], depth + 1] if n[:remote_ip] && in_scope.call(n[:remote_ip])
        end
      end
      devices
    end

    private

    def lldp_neighbors(ip, port_name)
      entries = Hash.new { |h, k| h[k] = {} }
      walk(ip, OID_LLDP_REM).each do |oid, value|
        column, time_mark, local_port, rem_index = oid.delete_prefix("#{OID_LLDP_REM}.").split('.')
        entries[[time_mark, local_port, rem_index]][column] = value
      end

      management = {}
      walk(ip, OID_LLDP_REM_MAN_ADDR).each do |oid, _value|
        # <time_mark>.<local_port>.<rem_index>.1.4.a.b.c.d  (subtype 1 = IPv4, length 4)
        match = oid.delete_prefix("#{OID_LLDP_REM_MAN_ADDR}.")
                   .match(/\A(\d+)\.(\d+)\.(\d+)\.1\.4\.(\d+\.\d+\.\d+\.\d+)\z/)
        management[match.captures[0..2]] = match[4] if match
      end

      entries.map do |key, cols|
        { protocol: 'lldp',
          local_port: port_name.call(key[1]),
          remote_ip: management[key],
          remote_mac: self.class.to_mac(cols['5']),
          remote_name: cols['9'].to_s.empty? ? nil : cols['9'],
          remote_port: [cols['8'], cols['7']].find { |v| !v.to_s.empty? } }
      end
    end

    def cdp_neighbors(ip, port_name)
      entries = Hash.new { |h, k| h[k] = {} }
      walk(ip, OID_CDP_CACHE).each do |oid, value|
        column, if_index, dev_index = oid.delete_prefix("#{OID_CDP_CACHE}.").split('.')
        entries[[if_index, dev_index]][column] = value
      end

      entries.map do |key, cols|
        { protocol: 'cdp',
          local_port: port_name.call(key[0]),
          remote_ip: self.class.hex_to_ip(cols['4']),
          remote_mac: nil,
          remote_name: cols['6'].to_s.empty? ? nil : cols['6'],
          remote_port: cols['7'].to_s.empty? ? nil : cols['7'] }
      end
    end

    def walk(ip, oid)
      raw = @runner ? @runner.call(ip, oid) : run_snmpwalk(ip, oid)
      self.class.parse_walk(raw)
    end

    def run_snmpwalk(ip, oid)
      env = { 'SNMPCONFPATH' => conf_dir, 'SNMP_PERSISTENT_FILE' => File.join(conf_dir, 'persist') }
      out, _err, status = Open3.capture3(env, 'snmpwalk', '-Oqn', '-t', @timeout.to_s, '-r', '1', ip, oid)
      status.success? ? out : ''
    rescue Errno::ENOENT
      warn '[!] snmpwalk not found, install net-snmp-utils'
      ''
    end

    def conf_dir
      @conf_dir ||= Dir.mktmpdir('rb-snmp').tap do |dir|
        path = File.join(dir, 'snmp.conf')
        File.write(path, conf_content)
        File.chmod(0o600, path)
      end
    end

    def conf_content
      lines = ["defVersion #{@config[:version]}"]
      if @config[:version] == '3'
        lines << "defSecurityName #{quote(@config[:username])}"
        lines << "defSecurityLevel #{@config[:security_level]}" unless @config[:security_level].to_s.empty?
        lines << "defAuthType #{@config[:auth_protocol].to_s.upcase}" unless @config[:auth_protocol].to_s.empty?
        lines << "defAuthPassphrase #{quote(@config[:auth_password])}" unless @config[:auth_password].to_s.empty?
        lines << "defPrivType #{@config[:priv_protocol].to_s.upcase}" unless @config[:priv_protocol].to_s.empty?
        lines << "defPrivPassphrase #{quote(@config[:priv_password])}" unless @config[:priv_password].to_s.empty?
      else
        lines << "defCommunity #{quote(@config[:community])}"
      end
      lines.join("\n") + "\n"
    end

    def quote(value)
      value = value.to_s
      raise ArgumentError, 'SNMP value contains a newline' if value.match?(/[\r\n]/)

      value.match?(/[\s#"]/) ? "\"#{value.gsub('\\', '\\\\\\\\').gsub('"', '\"')}\"" : value
    end
  end
end
