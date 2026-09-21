require 'minitest/autorun'
require_relative '../resources/scripts/rb_network_topology'

class NetworkTopologyTest < Minitest::Test
  def scanner
    Redborder::NetworkTopology.new('10.0.0.0/24')
  end

  def xml(hops, address = '10.0.0.9')
    <<~XML
      <?xml version="1.0"?>
      <!DOCTYPE nmaprun>
      <nmaprun><host><status state="up"/>
      <address addr="#{address}" addrtype="ipv4"/>
      <trace>#{hops}</trace></host>
      <runstats><finished exit="success"/></runstats></nmaprun>
    XML
  end

  def test_consecutive_hops_form_links_without_fabricating_host_attachment
    result = scanner.parse(xml('<hop ttl="1" ipaddr="192.168.1.1"/>' \
                               '<hop ttl="2" ipaddr="10.0.0.1"/>'))
    assert_equal 3, result['nodes'].size
    assert_equal [{ 'source' => '192.168.1.1', 'target' => '10.0.0.1',
                    'evidence' => 'traceroute' }], result['links']
  end

  def test_missing_hops_are_not_bridged
    result = scanner.parse(xml('<hop ttl="1" ipaddr="192.168.1.1"/>' \
                               '<hop ttl="3" ipaddr="10.0.0.9"/>'))
    assert_empty result['links']
  end

  def test_no_trace_still_produces_an_isolated_host
    result = scanner.parse(xml(''))
    assert_equal ['10.0.0.9'], result['nodes'].map { |node| node['ip'] }
    assert_empty result['links']
  end

  def test_out_of_scope_hosts_are_not_added_but_transit_hops_are_allowed
    assert_empty scanner.parse(xml('', '172.16.0.2'))['nodes']
    assert scanner.parse(xml('<hop ttl="1" ipaddr="192.168.1.1"/>'))['nodes']
                  .any? { |node| node['ip'] == '192.168.1.1' }
  end

  def test_target_is_not_expanded_and_command_uses_separate_arguments
    single = Redborder::NetworkTopology.new('10.0.0.9')
    assert_equal '10.0.0.9', single.command.last
    assert_includes single.command, '--traceroute'
    assert_includes single.command, '-sn'
    assert_raises(ArgumentError) { Redborder::NetworkTopology.new('10.0.0.0/16') }
    assert_raises(ArgumentError) { Redborder::NetworkTopology.new('10.0.0.1;id') }
  end

  def test_failed_nmap_and_external_entities_are_rejected
    assert_raises(RuntimeError) { scanner.parse(xml('').sub('exit="success"', 'exit="error"')) }
    assert_raises(ArgumentError) { scanner.parse('<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">') }
  end

  def test_event_contract_and_metadata_cannot_override_scan_id
    event = scanner.event(scanner.parse(xml('')), 42,
                          { 'uuid' => 'sensor-a', 'name' => 'Scanner A', 'scan_id' => '999' })
    assert_equal '42', event['scan_id']
    assert_equal 'sensor-a', event['sensor_uuid']
    assert_equal 1, JSON.parse(event['topology_json'])['schema_version']
    assert_equal 'network_topology', event['scan_type']
  end
end
