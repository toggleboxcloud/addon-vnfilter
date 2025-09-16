#!/bin/bash
# Debug script for VRRP vnfilter configuration

if [ -z "$1" ]; then
    echo "Usage: $0 <vm_id>"
    exit 1
fi

VM_ID=$1

echo "=== VRRP VNFilter Debug for VM $VM_ID ==="
echo

# Check VM configuration
echo "1. VM Configuration:"
onevm show $VM_ID | grep -E "(^ID|^NAME|VIP_NIC|VMAC_NIC|NIC_ID|IP |MAC |FILTER_)"
echo

# Check ipsets
echo "2. IPSets for VM $VM_ID:"
for nic in 0 1 2; do
    ipset_name="one-${VM_ID}-${nic}-ip-spoofing"
    if ipset list $ipset_name 2>/dev/null; then
        echo "Found ipset: $ipset_name"
        ipset list $ipset_name | grep -E "(Members:|^[0-9])"
        echo
    fi
done

# Check iptables rules
echo "3. IPTables rules for VM $VM_ID:"
for nic in 0 1 2; do
    chain="one-${VM_ID}-${nic}-o"
    if iptables -L $chain -n 2>/dev/null | grep -q .; then
        echo "Chain $chain:"
        iptables -L $chain -n -v
        echo
    fi
done

# Check ebtables rules
echo "4. EBTables NAT rules for VM $VM_ID:"
ebtables -t nat -L | grep -A20 "one-${VM_ID}" | grep -v "^$"
echo

# Check running VM interfaces
echo "5. VM Network Interfaces:"
virsh domiflist one-$VM_ID 2>/dev/null
echo

# Check syslog for vnfilter messages
echo "6. Recent vnfilter log messages:"
journalctl -u syslog --since "10 minutes ago" | grep vnfilter | tail -20
echo

# Check if VRRP processes are running in the VM
echo "7. VRRP Status (if accessible):"
if which virsh >/dev/null 2>&1; then
    # Try to get VM IP
    VM_IP=$(onevm show $VM_ID | grep "IP=" | head -1 | cut -d'"' -f2)
    if [ -n "$VM_IP" ]; then
        echo "VM IP: $VM_IP"
        # This would need SSH access to the VM
        echo "To check VRRP status inside VM, run:"
        echo "  ssh root@$VM_IP 'ps aux | grep -E \"(keepalived|vrrp)\"'"
        echo "  ssh root@$VM_IP 'ip addr show | grep -E \"(00:00:5e|vrrp)\"'"
    fi
fi
echo

echo "=== End of Debug Output ==="
