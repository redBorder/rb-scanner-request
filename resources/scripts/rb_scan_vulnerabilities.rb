#######################################################################
# Copyright (c) 2014 ENEO Tecnologia S.L.
# This file is part of redBorder.
# redBorder is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# redBorder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with redBorder. If not, see <http://www.gnu.org/licenses/>.
#######################################################################

#!/usr/bin/env ruby

require 'net/http'
require 'net/https'
require "uri"
require 'active_support/core_ext/hash'
require 'json'
require 'poseidon'

module Redborder

  class VulnerabilitiesScan
    attr_accessor :address, :is_database
    attr_accessor :nmap_query, :response_hash, :general_info, :producer
    NMAP_PATH = "/usr/bin/nmap"

    def initialize

      @debug = false
      @address_list = [ARGV[0]]
      @address_list = 'localhost' if ARGV[0].nil?
      @ports = ARGV[1] unless (ARGV[1] == "debug" or ARGV[1].nil?)
      @ports = 'all' if (ARGV[1].nil? or ARGV[1] == "debug")
      @scan_id = ARGV[2] unless ARGV[2] == "debug"
      @enrichment = JSON.parse(ARGV[3]) unless ARGV[3] == "debug"
      if (!ARGV[1].nil? and ARGV[1] == "debug") or (!ARGV[2].nil? and ARGV[2] == "debug") or (!ARGV[3].nil? and ARGV[3] == "debug") or (ARGV[4] == "debug")
        @debug = true
      end
      @producer = Poseidon::Producer.new(["127.0.0.1:9092"], "vulnerabilities_cpe_producer")

      unless @enrichment == nil
        check_enrichment
      end
      set_target
    end

    def set_target
      @address_list.each do |address|
        @address = address
        if @address.include?("/")
          nmap_response = `#{NMAP_PATH} -sn -oX - #{@address}`
          response = Hash.from_xml(nmap_response)
          hosts = response["nmaprun"]["host"]

          if response["nmaprun"]["host"].class == Array
            hosts.each do |host|
              host_ip = get_host(host)
              @address = host_ip
              refresh_kafka_producer
              puts "\n------------------> Analysing (List): " + host_ip.to_s if @debug
              get_vulnerabilities(@ports, @scan_id)
            end
          else
            host_ip = get_host(response["nmaprun"]["host"])
            @address = host_ip
            refresh_kafka_producer
            puts "\n------------------> Analysing " + host_ip.to_s if @debug
            get_vulnerabilities(@ports, @scan_id)
          end
        else
          puts "\n------------------> Analysing (one host) " + @address if @debug
          get_vulnerabilities(@ports, @scan_id)
        end
      end
    end

    def refresh_kafka_producer
      @producer = Poseidon::Producer.new(["127.0.0.1:9092"], "vulnerabilities_cpe_producer")
    end

    def get_host(host)
      if host["address"].class != Array
        host["address"]["addr"]
      else
        host["address"].each do |address|
          if address["addrtype"] == "ipv4"
            return address["addr"]
          end
        end
      end
    end

    # Deletes nil fields
    def check_enrichment
      input = @enrichment
      field_list = %w[service_provider_uuid service_provider namespace namespace_uuid organization organization_uuid building building_uuid]

      input.each do | key, value |
        if field_list.include?(key) and ( value.empty? or value == "")
          @enrichment.delete(key)
        end
      end
    end

    # Method to produce to a kafka topic
    def produce_to_kafka(cpe_string, scan_id, topic)

      general = @general_info
      cpe = {"cpe" => cpe_string, "scan_id" => scan_id, "scan_type" => "2"}

      # Enrichment if the parameter was received
      if @enrichment != "{}" and !@enrichment.nil?
        cpe = cpe.merge(@enrichment)
      end

      msg = cpe.merge(general).to_json
      begin
        messages = []
        messages << Poseidon::MessageToSend.new(topic, msg)
        @producer.send_messages(messages)
      rescue
        p "Error producing messages to kafka #{topic}..."
      end
    end

    # NMAP Query
    # parameters
    #   => param: type of nmap query
    #   => ports: ports to scan (could be empty for all ports scan)
    def nmap_query(param, port)
      @parameters = ["-sV","-Pn","-v"]

      port=port.delete(' ')
      if port == "" then port = "all" end


      if port_eval(port) == true or port == "all"

        if port.downcase == "all"
          if @parameters.include? param
            @nmap_query = "IP: "+ @address + "\n" + `sudo nmap #{param} #{@address}`
          else
            @nmap_query = "IP: "+ @address + "\n" + `sudo nmap #{@address}`
          end
        else
          if @parameters.include? param
            @nmap_query = "IP: "+ @address + "\n" + `sudo nmap -p #{port.strip} #{param} #{@address}`
          else
            @nmap_query = "IP: " + @address + "\n" + `sudo nmap -p #{port.strip} #{@address}`
          end
        end
      else
        @nmap_query = "Incorrect Nmap port input: \n#{port}"
      end
    end


    # Get CPE List from a NMAP response
    def get_cpe_list(response)
      cpe_list = []
      cpe_hash_list = {}
      cpe_ports = {}
      cpe_text = {}

      path = response["nmaprun"]["host"]["ports"]["port"]
      if path != nil ##not closed ports
        unless path.class == Array
          path = [path]
        end
        path.each do |service|
          if service.class == Hash
            if service["service"]["cpe"] != nil ## if service has cpe
              cpe = check_deprecated(service["service"]["cpe"])
              if service["service"]["product"] != nil
                cpe_text[cpe] = "\nPort: " + service["portid"] + "  " + service["service"]["product"].to_s + " " + service["service"]["version"].to_s + "\n"
              end
              portid = service["portid"]

              if cpe.class == Array ## if cpe is a list of cpe (could be two cpe)

                aplication = ""
                for cpe_aux in cpe
                  if cpe_aux.include? "cpe:/a:"
                    aplication = cpe_aux
                  end
                end
                cpe = aplication
              end

              if cpe.include? "cpe:/a:" #repeat service control
                insert = true
                cpe_list.each do |element|
                  if element.include? cpe
                    insert = false
                  end
                end
                if insert
                  cpe_list.append(cpe)
                  if service["service"]["product"] != ""
                    @response_hash["ports"][portid] = {}
                    @response_hash["ports"][portid]["product"] = service["service"]["product"]
                    @response_hash["ports"][portid]["version"] = service["service"]["version"]
                    @response_hash["ports"][portid]["name"] = service["service"]["name"]
                    @response_hash["ports"][portid]["protocol"] = service["protocol"]
                    @response_hash["ports"][portid]["port_state"] = service["state"]["state"]
                    #assign ports and cpe in hash
                    cpe_ports[cpe] = portid
                  end
                end
              end
            end
          end
        end
        cpe_list = cpe_list.uniq
        {"cpe_list" => cpe_list, "cpe_ports" => cpe_ports, "cpe_text" => cpe_text}
      else ## closed ports
        {}
      end
    end

    # Eval port format input
    # examples of acepted input:
    #   - 22,30,8080
    #   - 22,8000-8080
    #   - all
    def port_eval(ports)
      pass = true
      ports = ports.split(",").collect(&:strip)
      ports.each { |port|
        range_ports = /(^[\d]\d{0,4}-?\d{1,5})/.match(port)
        if range_ports != nil
          if range_ports.to_s.include?("-")
            port_split = range_ports.to_s.split('-')
            if port_split[0].to_i < port_split[1].to_i
            else
              pass = false
            end
          else
            if port.to_s.match(/\D/) != nil
              pass = false
            end
          end
        else
          singleport = /[1-9]/.match(port)
          if singleport != nil
            if port.match(/\D/) != nil
              pass = false
            end
          else
            pass = false
          end
        end
      }
      if pass
        true
      else
        false
      end
    end

    # Main vulnerabilities function
    # Parameters:
    # => port: ports to scan (could be empty for all ports scan)
    def get_vulnerabilities(port, scan_id)
      @response_hash = {}
      @general_info = {}

      port = port.delete(' ')

      if port == "" then port="all" end

      if port_eval(port) or port == "all"
        if port.to_i < 0 or port.downcase == "all"
          response = `#{NMAP_PATH} -sV -n -oX - #{@address}`
        else
          response = `#{NMAP_PATH} -p #{port.strip} -sV -n -oX - #{@address}`
        end
        nmap_response = Hash.from_xml(response)

        # Check if server is alive:
        server_up = nmap_response["nmaprun"]["runstats"]["hosts"]["up"]
        puts "IP: "+@address+"\n" if @debug
        if server_up == '1'

          cpe_list=[]
          @response_hash["ports"] = {}

          if nmap_response["nmaprun"]["host"]["address"].class != Array
            @general_info["ipv4"] = nmap_response["nmaprun"]["host"]["address"]["addr"]
          else
            nmap_response["nmaprun"]["host"]["address"].each do |address|
              @general_info["ipv4"] = address["addr"] if address["addrtype"] == "ipv4"
              @general_info["mac"] = address["addr"] if address["addrtype"] == "mac"
            end
          end

          @general_info["timestamp"] = nmap_response["nmaprun"]["start"].to_i

          cpe_info = get_cpe_list(nmap_response)

          if !cpe_info.empty?
            cpe_list = cpe_info["cpe_list"]
            cpe_ports = cpe_info["cpe_ports"]
            cpe_text = cpe_info["cpe_text"]

            cpe_list.each do |cpe|

              puts "\n" + "------------------------------\n" + "\nVulnerabilities:  " + cpe + "\n" if @debug

              if cpe_text[cpe] != nil
                puts cpe_text[cpe] if @debug
              end

              cpe_string = cpe.gsub("cpe:/a", "cpe:2.3:a")

              if cpe.include? "%2B" ## cleaning trash in nmap code
                cpe_aux = cpe_string.split("%2B")
                cpe_string = cpe_aux[0]
                cpe_string = cpe_string + "*"
              end

              @general_info["product"] = @response_hash["ports"][cpe_ports[cpe]]["product"] if @response_hash["ports"][cpe_ports[cpe]]["product"] != nil
              @general_info["version"] = @response_hash["ports"][cpe_ports[cpe]]["version"] if @response_hash["ports"][cpe_ports[cpe]]["version"] != nil
              @general_info["servicename"] = @response_hash["ports"][cpe_ports[cpe]]["name"] if @response_hash["ports"][cpe_ports[cpe]]["name"] != nil
              @general_info["protocol"] = @response_hash["ports"][cpe_ports[cpe]]["protocol"] if @response_hash["ports"][cpe_ports[cpe]]["protocol"] != nil
              @general_info["port_state"] = @response_hash["ports"][cpe_ports[cpe]]["port_state"] if @response_hash["ports"][cpe_ports[cpe]]["port_state"] != nil
              @general_info["port"] = cpe_ports[cpe]

              produce_to_kafka(cpe_string, scan_id, "rb_scanner")
              puts "Kafka message sent: " + cpe_string.to_s if @debug
            end
            @producer.close()
          else
            puts "All Ports closed in #{address} " if @debug
          end
        else
          puts "Server with IP #{address} down." if @debug
        end
      end
    end

    def check_deprecated(cpe)
      deprecated_cpe = { "igor_sysoev:nginx" => "nginx:nginx"}
      deprecated_cpe.each_pair do |key, value|
        if cpe.include?(key)
          cpe.gsub!(key,value)
        end
      end
      cpe
    end
  end
end

nmap = Redborder::VulnerabilitiesScan.new()
