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
require 'getopt/std'

module Redborder

  class Scanner
    attr_accessor :address, :is_database
    attr_accessor :nmap_query, :response_hash, :general_info, :kafka_producer
    NMAP_PATH = "/usr/bin/nmap"
    # MAX_NMAP_ARGUMENTS = 129000

    def initialize(target, ports, scan_id, enrichment, batch_rate, kafka_broker, debug)
      @target = target
      @ports = ports
      @scan_id = scan_id
      @enrichment = enrichment.reject{ |kev,value| 
                      %w[service_provider_uuid service_provider 
                         namespace namespace_uuid 
                         organization organization_uuid 
                         building building_uuid].include? key and value.empty?
                     }
      @batch_rate = batch_rate
      @kafka_id = "vulnerabilities_cpe_producer"
      @kafka_broker = kafka_broker
      @debug = debug       
    end

    #Convert batch_rate to a natural number, in order to split ports
    def set_batch_step (number_of_ports=65535)
      @batch_step = number_of_ports * @batch_rate
      @batch_step = @batch_step < 1.0 ? 1 : @batch_step.round
    end 

    def start
      @target.each do |address|
        @address = address
        if @address.include?("/")
          nmap_response = `#{NMAP_PATH} -sn -oX - #{@address}`
          response = Hash.from_xml(nmap_response)
          hosts = response["nmaprun"]["host"]

          if response["nmaprun"]["host"].class == Array
            hosts.each do |host|
              host_ip = get_host(host)
              @address = host_ip
              puts "\n------------------> Analysing (List): " + host_ip.to_s if @debug
              get_vulnerabilities(@ports, @scan_id)
            end
          else
            host_ip = get_host(response["nmaprun"]["host"])
            @address = host_ip
            puts "\n------------------> Analysing " + host_ip.to_s if @debug
            get_vulnerabilities(@ports, @scan_id)
          end
        else
          puts "\n------------------> Analysing (one host) " + @address if @debug
          get_vulnerabilities(@ports, @scan_id)
        end
      end
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

    # Method to produce to a kafka topic
    def produce_to_kafka(cpe_string, scan_id, topic)
      @kafka_producer = Poseidon::Producer.new([@kafka_broker], @kafka_id)
      general = @general_info
      cpe = {"cpe" => cpe_string, "scan_id" => scan_id, "scan_type" => "2"}
      # Enrichment if the parameter was received
      cpe = cpe.merge(@enrichment)
      cpe = cpe.merge(general)
      begin
        messages = []
        messages << Poseidon::MessageToSend.new(topic, cpe.to_json)
        @kafka_producer.send_messages(messages)
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
      if path != nil ##not closed ports.    Not really: port 36 is closed but appears here
        unless path.class == Array
          path = [path]
        end
        path.each do |service|
	        is_valid_service = service.class == Hash && service["service"] != nil && service["service"]["cpe"] != nil
          if is_valid_service
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

    #Converts ports sequence with singles and ranges to all singles
    #ie: ["3-5","8","10"] => ["3","4","5","8","10"]
    def expand_ranges(ports)
      ports.map! do |port_range|    #each element is either single or range.  !: means that ports is going to change
        range = port_range.split('-')
        singles = port_range.size > 1 ? Array(range.first..range.last) : port_range      #If single do nothing
      end
      ports.flatten
    end

    def get_default_ports #(protocol=:tcp)
      # protocol_arg = '-sT' if protocol == :tcp
      # protocol_arg = '-sU' if protocol == :udp
      # response = `#{NMAP_PATH} #{protocol_arg} -oX -` #get default ports to sniff
      response = `#{NMAP_PATH} -sV -oX -` #get default ports to sniff
      map = Hash.from_xml(response)
      ports = map["nmaprun"]["scaninfo"]["services"]
    end

    # Groups the ports in batches, generating a 2 dimensional array for the ports
    # ie: with @batch_rate = 0.25 => input "1,3-6,8,11-12" => output[["1", "3"] , ["4-5"], ["6","8"], ["11-12"]]
    def get_ports_batched(ports)
      #prepare ports
      ports = ports.split(',')      #string with commas to array
      ports = expand_ranges(ports)  #convert ranges to singles
      ports.uniq!                   #remove duplicated
      #batch
      set_batch_step(ports.size)
      ports.each_slice(@batch_step).to_a
    end

    # Compress expanded ports in order to give less arguments to nmap call
    # ie: ["1", "2", "3", "6", "8", "9"] => ["1-3","6","8-9"]
    def compress_ranges(ports)
      ports.map!(&:to_i)    #elements to integer
      compressed_ports = []
      _a = 0                #first_index: analyze forward here
      while (_a < ports.size)
        _z = _a + 1         #last index: stops when non consecutive
        while (ports[_z] == ports[_z-1]+1) and !ports[_z+1].nil?  # if consecutive and prevent out of bounds
          _z += 1           #look the next one
        end
        has_consecutives = _z - _a > 1
        range = has_consecutives ? ports[_a].to_s + '-' + ports[_z-1].to_s : ports[_a].to_s
        compressed_ports.append(range)
        _a = _z
      end
      compressed_ports
    end

    # Main vulnerabilities function
    # Parameters:
    # --- port: ports to scan (could be empty or 'all' for top 1000 default value of nmap, or a sequence of numbers a string
    # --- scan_id: id needed to identify which scan is running for producing to the web
    def get_vulnerabilities(ports, scan_id)
      ports = get_default_ports if (ports == "all" or ports=="")
      port_batches = get_ports_batched(ports)
      for ports in port_batches
        # ports_stream = ports.join(",")
        # ports = ports_stream.size > MAX_NMAP_ARGUMENTS ? compress_ranges(ports) : ports_stream   #Only when necessary, because we want that nmap takes longer
        ports = compress_ranges(ports)
        ports = ports.join(',')
      	p "ANALIZING PORTS: " + ports.to_s if @debug
        response = `#{NMAP_PATH} -p #{ports} -sV -n -oX - #{@address}`
        nmap_response = Hash.from_xml(response)

        # Check if server is alive:
        server_up = nmap_response["nmaprun"]["runstats"]["hosts"]["up"]
        puts "IP: "+@address+"\n" if @debug

        @response_hash = {}
        @general_info = {}
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
            sleep (60-Time.now.sec) #produce once for each min
            @kafka_producer.close() if @kafka_producer
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

# MAIN
opt = Getopt::Std.getopts("t:p:s:e:b:k:d")
# Initialize variables
target       = (opt["t"] || "localhost").split #Array
ports        = opt["p"] || "all"
scan_id      = opt["s"] || raise {"ERROR: please assing scan id"}
kafka_broker = opt["k"] || "127.0.0.1:9092"
batch_rate   = opt["b"].nil? ? 0.1 : opt["b"].to_f
debug        = opt["d"] || false
enrichment   = JSON.parse(opt["e"]) rescue {}

if batch_rate < 0.0 or batch_rate > 1.0
  puts "ERROR: batch rate value should be between 0.0 and 1.0"
  exit 1
end

scanner = Redborder::Scanner.new(target, ports, scan_id, enrichment, batch_rate, kafka_broker, debug)
scanner.start
