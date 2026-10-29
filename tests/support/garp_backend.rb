# Exercise the production builders and reconciliation against an isolated kernel.
require 'json'
module VNMMAD
    class VNMDriver; end
end
$LOADED_FEATURES << 'vnmmad.rb'
require_relative '../../remotes/vnm/vnfilter'
load File.expand_path('../../host/vnfilter_arp_guard_nft', __dir__)

action, *args = ARGV
backend = AddonFirewallSafety::Backend.new(tool: 'ebtables', table: 'nat')
case action
when 'build'
    tap, mac, *ips = args
    filter = VnFilter.allocate
    filter.instance_variable_set(:@slog, Object.new.tap { |logger| def logger.info(*); end })
    filter.instance_variable_set(:@ebtables_backend, backend)
    filter.deactivate_ebtables(tap)
    commands = filter.build_mac_spoofing_ebtables_commands(tap, "#{tap}-i", "#{tap}-o", { mac: mac }, { ip4: ips })
    filter.execute_ebtables_commands!(tap, commands)
when 'cleanup'
    filter = VnFilter.allocate
    filter.instance_variable_set(:@slog, Object.new.tap { |logger| def logger.info(*); end })
    filter.instance_variable_set(:@ebtables_backend, backend)
    filter.deactivate_ebtables(*args)
when 'refresh'
    puts VnfilterGratuitousArp.refresh(backend, action: args.fetch(0))
when 'guard'
    mode, directory, *targets = args
    manager = VnfilterArpGuardNft::Manager.new(state_directory: directory, state_path: File.join(directory, 'owner.json'))
    manager.apply(JSON.generate('version' => 1, 'mode' => mode, 'ingress_interface' => 'bond0.1', 'targets' => targets))
else
    abort 'invalid backend action'
end
