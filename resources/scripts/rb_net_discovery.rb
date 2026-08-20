#!/usr/bin/ruby

#######################################################################
## Copyright (c) 2014 ENEO Tecnología S.L.
## This file is part of redBorder.
## redBorder is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## redBorder is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License License for more details.
## You should have received a copy of the GNU Affero General Public License License
## along with redBorder. If not, see <http://www.gnu.org/licenses/>.
########################################################################

#!/usr/bin/env ruby

require 'json'
require 'resolv'
require 'ipaddress'

class NetworkDiscovery
  APIPA_NET = "169.254.0.0"
  NETMASKS = ["/16", "/18", "/19", "/20", "/21", "/22", "/23", "/24", "/25", "/26", "/27", "/28", "/29", "/30"]

  attr_reader :target, :discovered_subnets

  def initialize(target)
    @target = IPAddress(target)
    @discovered_subnets = []
  end

  def scan
    scan_iptables
    scan_netstat
    filter_and_add_target
    discovered_subnets.uniq
  end

  private

  def scan_iptables
    puts "\nGathering information from Iptables..."
    response = `iptables -L` rescue nil
    return unless response

    subnets = parse_iptables_response(response)
    @discovered_subnets.concat(subnets)
    puts subnets.join("\n")
  end

  def parse_iptables_response(response)
    response.each_line.with_object([]) do |line, subnets|
      next unless line.include?("ACCEPT")

      NETMASKS.each do |mask|
        subnets.concat(line.scan(/\b\d{1,3}(?:\.\d{1,3}){3}#{mask}\b/))
      end

      ips = extract_ips(line)
      subnets.concat(ips)
    end.uniq
  end

  def extract_ips(line)
    line.scan(/\b\d{1,3}(?:\.\d{1,3}){3}\b/).map do |ip|
      base = ip.split('.')[0..2].join('.')
      "#{base}.0/24"
    end
  end

  def scan_netstat
    puts "\nGathering information from Netstat..."
    response = `netstat -nr` rescue nil
    return unless response

    parse_netstat_response(response)
  end

  def parse_netstat_response(response)
    rows = parse_netstat_table(response)
    rows.each do |row|
      dest = row["Destination"]
      genmask = row["Genmask"]
      next if dest.nil? || dest == "0.0.0.0" || dest == APIPA_NET
      next if genmask.nil? || genmask.empty?

      net = begin
        IPAddress("#{dest}/#{genmask}").to_string
      rescue
        next
      end

      puts net
      @discovered_subnets << net
    end
  end

  # Locates the header row by content (rather than assuming a fixed line
  # number, which breaks if the table has extra/missing banner lines) and
  # only accepts rows whose column count matches the header, so a
  # misaligned line produces no entry instead of a garbage hash.
  def parse_netstat_table(response)
    lines = response.lines.map(&:rstrip)
    header_index = lines.index { |l| l.include?("Destination") && l.include?("Genmask") }
    return [] unless header_index

    headers = lines[header_index].split
    lines[(header_index + 1)..-1].each_with_object([]) do |line, rows|
      next if line.strip.empty?

      values = line.split
      next unless values.size == headers.size

      rows << Hash[headers.zip(values)]
    end
  rescue
    []
  end

  def filter_and_add_target
    relevant = @discovered_subnets.select do |subnet|
      begin
        subnet_obj = IPAddress(subnet)
        subnet_obj.include?(@target) || @target.include?(subnet_obj)
      rescue
        false
      end
    end

    unless relevant.any? { |s| IPAddress(s).include?(@target) }
      relevant << @target.to_string
    end

    @discovered_subnets = relevant
  end
end