#!/usr/local/bin/ruby
#AUTHOR: Javier Rodriguez Gomez
#VERSION: 15-12-20

require 'active_support/core_ext/hash'
require 'json'
require 'matrix'
require 'csv'
require 'poseidon'
require_relative './rb_net_discovery.rb'
require 'getopt/std'

module Redborder
class HostDiscovery

  attr_accessor :response, :hosts, :hosts_list, :network_hosts, :networks, :subnets, :path_list, :adjacency_matrix, :matrix_index, :new_found
  attr_accessor :redborder_ip, :kafka_producer
  #TRACEROUTE_PATH = "/usr/bin/traceroute"
  TRACEROUTE_PATH = "/bin/traceroute"

  # Call the subnet discovery algorithm
  def get_subnets
    return NetworkDiscovery.scanner()
  end

       def initialize(target, ports, scan_id, enrichment, batch_rate, kafka_broker, debug)
      @target = target
      @ports = ports
      @scan_id = scan_id
      @enrichment = enrichment.reject{ |key,value|
                      %w[service_provider_uuid service_provider 
                         namespace namespace_uuid 
                         organization organization_uuid 
                         building building_uuid].include? key and value.empty?
                     } #if any of this fields is empty, remove it
      @batch_rate = batch_rate
      @kafka_id = "vulnerabilities_cpe_producer"
      @kafka_broker = kafka_broker
      @debug = debug
    end

  # Main program
  def discover
    @hosts = []
    @path_list = []
    @subnets = get_subnets
    @networks = {}
    @newfound = []

    puts "\n-------------------Subnets Discovered------------------------------"
    puts @subnets

    @subnets.each do | net |
      puts "\n-----------------------#{net}-------------------------------"
      puts "Host Discovery: \n"
      begin
        nmap_scan_with_traceroute(net)
        puts "\n#{net} results: "
        puts @network_hosts.to_json
      rescue
        puts "\n#{net} not reachable"
      end
    end

    puts "\nNetwork Results"
    puts @networks
    puts "\n"
    set_matrix_path()
    export_data()
  end

# Processes and prints information of a host from Nmap scan results, and stores relevant data in instance variables, returning the host IP.
def process_host(host)
    addresses = [host["address"]].flatten
    host_ip = nil # Inicializa a nil por defecto

    addresses.each do |address|
        case address["addrtype"]
        when "ipv4"
            host_ip = address["addr"]
            @hosts_list.push(host_ip)
            @network_hosts[host_ip] ||= {} # Inicializa el hash si no existe
            @network_hosts[host_ip]["ipv4"] = host_ip
            puts host_ip
        when "mac"
            @network_hosts[host_ip]["mac"] = address["addr"] if host_ip
            puts address["addr"]
        end

        if address["vendor"]
            @network_hosts[host_ip]["vendor"] = address["vendor"] if host_ip
            puts address["vendor"]
        end
    end

    if host["hostnames"] && host["hostnames"]["hostname"]
        hostname = host["hostnames"]["hostname"]["name"]
        @network_hosts[host_ip]["hostname"] = hostname if hostname && host_ip
        puts hostname
    end

   if host["os"] && host["os"]["osmatch"]
        os_info = host["os"]["osmatch"]

        os_name = os_info.is_a?(Array) ? os_info.first["name"] : os_info["name"]

        @network_hosts[host_ip]["os"] = os_name if host_ip && os_name
        puts os_name
    end
  return host_ip
end

  # Produces and sends a JSON message to a specified Kafka topic, and prints the message or error if any occur.
  def produce_to_kafka(data_hash, topic)
  @kafka_producer = Poseidon::Producer.new([@kafka_broker], @kafka_id)

  begin
    messages = []
    messages << Poseidon::MessageToSend.new(topic, data_hash.to_json)
    p messages
    @kafka_producer.send_messages(messages)
  rescue
    p "Error producing messages to kafka #{topic}..."
  end
end


  # Reverse lookup function used to detect if an ip is from a website
  def reverse_lookup(ip)
    response = `host #{ip}`

    if !response.include? "not found:"
      last = response.split(" ").last()
      return last.delete_suffix!(".")
    else
      return nil
    end
  end

  # Performs an Nmap SYN scan with OS detection and traceroute, and prints the results for the specified network/host.
  def nmap_scan_with_traceroute(net)
  @response = `nmap -T5 -O -sS --traceroute -oX - #{net}`
  nmap_response = Hash.from_xml(@response)
  puts nmap_response
  mapping_result(nmap_response, net)
end

# Processes Nmap scan results, updates host information and network-host mappings for the specified network/host.
def mapping_result(response, net)
  @hosts_list = []
  @network_hosts = {}


  hosts = [response["nmaprun"]["host"]].flatten

  hosts.each do |host|
    host_ip = process_host(host)

    if host["trace"] && host["trace"]["hop"]
      hops = [host["trace"]["hop"]].flatten
      process_traceroute(hops, host_ip)
    else
      puts "No trace data found for host."
    end
  end

@hosts |= @hosts_list


  if @networks[net]
      @networks[net].merge!(@network_hosts)
  else
      @networks[net] = @network_hosts
  end
end

 # Processes traceroute hops to construct and store the path, and adds hostname information to the target host if available.
 def process_traceroute(hops, target_host_ip)
  path = {}
  last_hop = get_redborder_ip

  hops.each do |hop|
    ip = hop["ipaddr"]
    path[last_hop] = ip

    if ip == target_host_ip && @network_hosts[target_host_ip]["hostname"].nil? && hop["host"]
      @network_hosts[target_host_ip]["hostname"] = hop["host"]
    end
    last_hop = ip
  end

  store_path(path)
end

  def get_redborder_ip
    @redborder_ip ||= `hostname -I`.split(" ")[0]
  end
  # look for new subnets in each hop
  # Store the source - > target hop path
  def store_path(path)
  @path_list.push(path)

  path.each do |host_pair|
    host_pair.each do |host|
      add_host_and_subnet(host) unless @hosts.include? host
    end
  end
 puts "@path_list before set_matrix_path: #{@path_list.inspect}"

end

# Adds a new host and its associated subnet to instance data structures, and prints messages upon discovering new entities.
def add_host_and_subnet(host)
  puts "-------------------------------------------------<New host found!!"
  host_subnet = extract_subnet(host)

  unless @subnets.include? host_subnet
    @subnets.push(host_subnet)
    puts "------------------------------------------------->New Subnet Found!!"
    @networks[host_subnet] ||= {}
    @networks[host_subnet][host] = { "ipv4" => host }
  end

  @hosts.push(host) unless @hosts.include?(host)

end

def extract_subnet(ip)
  ip.split('.')[0..2].join('.') + ".0/24"
end


 # just print the adjacency matrix
def print_matrix
  @adjacency_matrix.each do |row|
    puts row.join(" ")
  end
end

# Create the adjacency matrix
def set_matrix_path
  fill_index()


  # Initialize the matrix with 0s and set the diagonal to 1s
  @adjacency_matrix = Array.new(@hosts.size) do |i|
    Array.new(@hosts.size) { |j| i == j ? 1 : 0 }
  end


  # Populate the matrix with the paths
  @path_list.each do |path|
    puts "Processing path: #{path.inspect}"

    path.each do |source, target|
      index_source = @matrix_index[source]
      index_target = @matrix_index[target]

      @adjacency_matrix[index_source][index_target] = 1
      @adjacency_matrix[index_target][index_source] = 1
    end
  end



  # Connect 192.168.122.1 to redborder_ip
  if @matrix_index.has_key?('192.168.122.1')
    redborder_ip_index = @matrix_index[get_redborder_ip]
    ip_122_1_index = @matrix_index['192.168.122.1']


    @adjacency_matrix[redborder_ip_index][ip_122_1_index] = 1
    @adjacency_matrix[ip_122_1_index][redborder_ip_index] = 1

 end


end

# fill the adjacency matrix with 0
def fill_index
  @matrix_index = {}
  @hosts.uniq.each_with_index do |host, index|
    @matrix_index[host] = index
  end

end
  # Export the data to /tmp/
  # A file with the host data info and another with the path between hosts
  def export_data
  # Directorios y nombres de archivo para CSV
  matrix_directory = "/root/rb-rails/tmp/"
  matrix_file = "matrix.csv"
  matrix_index = "matrix_index.csv"

  # Exportar la matriz de adyacencia a un archivo CSV
  CSV.open(matrix_directory + matrix_file, "wb") do |csv|
    @adjacency_matrix.each do |row|
      csv << row
    end
  end

  # Inicializar listas para almacenar información del host
  host_hostname = []
  host_vendor = []
  host_macs = []
  host_subnet = []
  host_os = []

  # Recoger información del host
  @hosts.each do |host|
    host_data = get_host_info(host)
    puts "Host: #{host}"
    puts "Host Data: #{host_data.inspect}"

    host_hash = host_data[0]
    host_subnet.push("s" + @subnets.index(host_data[1]).to_s)

    host_macs.push(host_hash["mac"] || nil)
    host_hostname.push(host_hash["hostname"] || nil)
    host_os.push(host_hash["os"] || nil)
    host_vendor.push(host_hash["vendor"] || nil)
  end

  # Exportar información adicional sobre el host a un archivo CSV
  CSV.open(matrix_directory + matrix_index, "wb") do |csv|
    csv << @hosts
    index = Array.new(@hosts.size).fill { |i| i }
    csv << index
    csv << host_subnet
    csv << host_hostname
    csv << host_macs
    csv << host_vendor
    csv << host_os
  end

    # Preparar datos para enviar a Kafka
    kafka_data = {
      "timestamp" => Time.now.to_i,
      "adjacency_matrix" => @adjacency_matrix,
      "scan_id" => @scan_id,
      "scan_type" => "1",  # Ajustar según sea necesario
      "sensor_name" => "ScannerNetworkmap",  # Ajustar según sea necesario
      "sensor_uuid" => "0f9710f7-acad-4b0d-9a7a-b884504119b4",  # Ajustar según sea necesario
      "host" => @hosts,
      "index" => Array.new(@hosts.size).fill { |i| i },
      "subnet" => host_subnet,
      "hostname" => host_hostname,
      "macs" => host_macs,
      "vendors" => host_vendor,
      "oss" => host_os
    }
  
    # Enviar datos a Kafka
    produce_to_kafka(kafka_data, "rb_host_discovery")
  end
  
    # Searches for the specified host in the @networks data structure and returns the host information and associated network if found, printing a message for non-matching entries.
    def get_host_info(host)
  
      @networks.each do |network|
        network[1].each do |host_ip|
           if host == host_ip[0]
             # puts "\nfound!  " + host_ip.to_s + "\n"
             return host_ip[1], network[0]
           else
              puts "not found #{host} " +  host_ip[1].to_s
           end
        end
      end
    end
  
  end
  end
  
  opt = Getopt::Std.getopts("t:p:s:e:b:k:d")
  # Initialize variables
  target       = (opt["t"] || "localhost").split #Array
  ports        = opt["p"] || "all"
  scan_id      = opt["s"] || raise("ERROR: please assing scan id")
  kafka_broker = opt["k"] || "127.0.0.1:9092"
  batch_rate   = opt["b"].nil? ? 0.1 : opt["b"].to_f
  debug        = opt["d"] || false
  enrichment   = JSON.parse(opt["e"]) rescue {}
  
  if 0.0 > batch_rate or batch_rate > 1.0
    puts "ERROR: batch rate value should be between 0.0 and 1.0"
    exit 1
  end
  
  
  scan = Redborder::HostDiscovery.new(target, ports, scan_id, enrichment, batch_rate, kafka_broker, debug)
  scan.discover