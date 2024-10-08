// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ComputeCloud.inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs;
import com.pulumi.oci.ComputeCloud.inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs;
import com.pulumi.oci.ComputeCloud.inputs.AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs Empty = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs();

    /**
     * The domain name system (DNS) addresses that the Compute Cloud{@literal @}Customer infrastructure uses for the data center network.
     * 
     */
    @Import(name="dnsIps")
    private @Nullable Output<List<String>> dnsIps;

    /**
     * @return The domain name system (DNS) addresses that the Compute Cloud{@literal @}Customer infrastructure uses for the data center network.
     * 
     */
    public Optional<Output<List<String>>> dnsIps() {
        return Optional.ofNullable(this.dnsIps);
    }

    /**
     * Dynamic routing information for the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    @Import(name="infrastructureRoutingDynamics")
    private @Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs>> infrastructureRoutingDynamics;

    /**
     * @return Dynamic routing information for the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    public Optional<Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs>>> infrastructureRoutingDynamics() {
        return Optional.ofNullable(this.infrastructureRoutingDynamics);
    }

    /**
     * Static routing information for a rack.
     * 
     */
    @Import(name="infrastructureRoutingStatics")
    private @Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs>> infrastructureRoutingStatics;

    /**
     * @return Static routing information for a rack.
     * 
     */
    public Optional<Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs>>> infrastructureRoutingStatics() {
        return Optional.ofNullable(this.infrastructureRoutingStatics);
    }

    /**
     * Information about the management nodes that are provisioned in the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    @Import(name="managementNodes")
    private @Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs>> managementNodes;

    /**
     * @return Information about the management nodes that are provisioned in the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    public Optional<Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs>>> managementNodes() {
        return Optional.ofNullable(this.managementNodes);
    }

    /**
     * The hostname corresponding to the virtual IP (VIP) address of the management nodes.
     * 
     */
    @Import(name="mgmtVipHostname")
    private @Nullable Output<String> mgmtVipHostname;

    /**
     * @return The hostname corresponding to the virtual IP (VIP) address of the management nodes.
     * 
     */
    public Optional<Output<String>> mgmtVipHostname() {
        return Optional.ofNullable(this.mgmtVipHostname);
    }

    /**
     * The IP address used as the virtual IP (VIP) address of the management nodes.
     * 
     */
    @Import(name="mgmtVipIp")
    private @Nullable Output<String> mgmtVipIp;

    /**
     * @return The IP address used as the virtual IP (VIP) address of the management nodes.
     * 
     */
    public Optional<Output<String>> mgmtVipIp() {
        return Optional.ofNullable(this.mgmtVipIp);
    }

    /**
     * Addresses of the network spine switches.
     * 
     */
    @Import(name="spineIps")
    private @Nullable Output<List<String>> spineIps;

    /**
     * @return Addresses of the network spine switches.
     * 
     */
    public Optional<Output<List<String>>> spineIps() {
        return Optional.ofNullable(this.spineIps);
    }

    /**
     * The spine switch public virtual IP (VIP). Traffic routed to the Compute Cloud{@literal @}Customer infrastructure and  and virtual cloud networks (VCNs) should have this address as next hop.
     * 
     */
    @Import(name="spineVip")
    private @Nullable Output<String> spineVip;

    /**
     * @return The spine switch public virtual IP (VIP). Traffic routed to the Compute Cloud{@literal @}Customer infrastructure and  and virtual cloud networks (VCNs) should have this address as next hop.
     * 
     */
    public Optional<Output<String>> spineVip() {
        return Optional.ofNullable(this.spineVip);
    }

    /**
     * Domain name to be used as the base domain for the internal network and by  public facing services.
     * 
     */
    @Import(name="uplinkDomain")
    private @Nullable Output<String> uplinkDomain;

    /**
     * @return Domain name to be used as the base domain for the internal network and by  public facing services.
     * 
     */
    public Optional<Output<String>> uplinkDomain() {
        return Optional.ofNullable(this.uplinkDomain);
    }

    /**
     * Uplink gateway in the datacenter network that the Compute Cloud{@literal @}Customer connects to.
     * 
     */
    @Import(name="uplinkGatewayIp")
    private @Nullable Output<String> uplinkGatewayIp;

    /**
     * @return Uplink gateway in the datacenter network that the Compute Cloud{@literal @}Customer connects to.
     * 
     */
    public Optional<Output<String>> uplinkGatewayIp() {
        return Optional.ofNullable(this.uplinkGatewayIp);
    }

    /**
     * Netmask of the subnet that the Compute Cloud{@literal @}Customer infrastructure is connected to.
     * 
     */
    @Import(name="uplinkNetmask")
    private @Nullable Output<String> uplinkNetmask;

    /**
     * @return Netmask of the subnet that the Compute Cloud{@literal @}Customer infrastructure is connected to.
     * 
     */
    public Optional<Output<String>> uplinkNetmask() {
        return Optional.ofNullable(this.uplinkNetmask);
    }

    /**
     * Number of uplink ports per spine switch. Connectivity is identical on both spine switches. For example, if input is two 100 gigabyte ports; then port-1 and port-2 on both spines will be configured.
     * 
     */
    @Import(name="uplinkPortCount")
    private @Nullable Output<Integer> uplinkPortCount;

    /**
     * @return Number of uplink ports per spine switch. Connectivity is identical on both spine switches. For example, if input is two 100 gigabyte ports; then port-1 and port-2 on both spines will be configured.
     * 
     */
    public Optional<Output<Integer>> uplinkPortCount() {
        return Optional.ofNullable(this.uplinkPortCount);
    }

    /**
     * The port forward error correction (FEC) setting for the uplink port on the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    @Import(name="uplinkPortForwardErrorCorrection")
    private @Nullable Output<String> uplinkPortForwardErrorCorrection;

    /**
     * @return The port forward error correction (FEC) setting for the uplink port on the Compute Cloud{@literal @}Customer infrastructure.
     * 
     */
    public Optional<Output<String>> uplinkPortForwardErrorCorrection() {
        return Optional.ofNullable(this.uplinkPortForwardErrorCorrection);
    }

    /**
     * Uplink port speed defined in gigabytes per second. All uplink ports must have identical speed.
     * 
     */
    @Import(name="uplinkPortSpeedInGbps")
    private @Nullable Output<Integer> uplinkPortSpeedInGbps;

    /**
     * @return Uplink port speed defined in gigabytes per second. All uplink ports must have identical speed.
     * 
     */
    public Optional<Output<Integer>> uplinkPortSpeedInGbps() {
        return Optional.ofNullable(this.uplinkPortSpeedInGbps);
    }

    /**
     * The virtual local area network (VLAN) maximum transmission unit (MTU) size for the uplink ports.
     * 
     */
    @Import(name="uplinkVlanMtu")
    private @Nullable Output<Integer> uplinkVlanMtu;

    /**
     * @return The virtual local area network (VLAN) maximum transmission unit (MTU) size for the uplink ports.
     * 
     */
    public Optional<Output<Integer>> uplinkVlanMtu() {
        return Optional.ofNullable(this.uplinkVlanMtu);
    }

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs() {}

    private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs $) {
        this.dnsIps = $.dnsIps;
        this.infrastructureRoutingDynamics = $.infrastructureRoutingDynamics;
        this.infrastructureRoutingStatics = $.infrastructureRoutingStatics;
        this.managementNodes = $.managementNodes;
        this.mgmtVipHostname = $.mgmtVipHostname;
        this.mgmtVipIp = $.mgmtVipIp;
        this.spineIps = $.spineIps;
        this.spineVip = $.spineVip;
        this.uplinkDomain = $.uplinkDomain;
        this.uplinkGatewayIp = $.uplinkGatewayIp;
        this.uplinkNetmask = $.uplinkNetmask;
        this.uplinkPortCount = $.uplinkPortCount;
        this.uplinkPortForwardErrorCorrection = $.uplinkPortForwardErrorCorrection;
        this.uplinkPortSpeedInGbps = $.uplinkPortSpeedInGbps;
        this.uplinkVlanMtu = $.uplinkVlanMtu;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs $;

        public Builder() {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs();
        }

        public Builder(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs defaults) {
            $ = new AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dnsIps The domain name system (DNS) addresses that the Compute Cloud{@literal @}Customer infrastructure uses for the data center network.
         * 
         * @return builder
         * 
         */
        public Builder dnsIps(@Nullable Output<List<String>> dnsIps) {
            $.dnsIps = dnsIps;
            return this;
        }

        /**
         * @param dnsIps The domain name system (DNS) addresses that the Compute Cloud{@literal @}Customer infrastructure uses for the data center network.
         * 
         * @return builder
         * 
         */
        public Builder dnsIps(List<String> dnsIps) {
            return dnsIps(Output.of(dnsIps));
        }

        /**
         * @param dnsIps The domain name system (DNS) addresses that the Compute Cloud{@literal @}Customer infrastructure uses for the data center network.
         * 
         * @return builder
         * 
         */
        public Builder dnsIps(String... dnsIps) {
            return dnsIps(List.of(dnsIps));
        }

        /**
         * @param infrastructureRoutingDynamics Dynamic routing information for the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingDynamics(@Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs>> infrastructureRoutingDynamics) {
            $.infrastructureRoutingDynamics = infrastructureRoutingDynamics;
            return this;
        }

        /**
         * @param infrastructureRoutingDynamics Dynamic routing information for the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingDynamics(List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs> infrastructureRoutingDynamics) {
            return infrastructureRoutingDynamics(Output.of(infrastructureRoutingDynamics));
        }

        /**
         * @param infrastructureRoutingDynamics Dynamic routing information for the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingDynamics(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingDynamicArgs... infrastructureRoutingDynamics) {
            return infrastructureRoutingDynamics(List.of(infrastructureRoutingDynamics));
        }

        /**
         * @param infrastructureRoutingStatics Static routing information for a rack.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingStatics(@Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs>> infrastructureRoutingStatics) {
            $.infrastructureRoutingStatics = infrastructureRoutingStatics;
            return this;
        }

        /**
         * @param infrastructureRoutingStatics Static routing information for a rack.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingStatics(List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs> infrastructureRoutingStatics) {
            return infrastructureRoutingStatics(Output.of(infrastructureRoutingStatics));
        }

        /**
         * @param infrastructureRoutingStatics Static routing information for a rack.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureRoutingStatics(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationInfrastructureRoutingStaticArgs... infrastructureRoutingStatics) {
            return infrastructureRoutingStatics(List.of(infrastructureRoutingStatics));
        }

        /**
         * @param managementNodes Information about the management nodes that are provisioned in the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder managementNodes(@Nullable Output<List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs>> managementNodes) {
            $.managementNodes = managementNodes;
            return this;
        }

        /**
         * @param managementNodes Information about the management nodes that are provisioned in the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder managementNodes(List<AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs> managementNodes) {
            return managementNodes(Output.of(managementNodes));
        }

        /**
         * @param managementNodes Information about the management nodes that are provisioned in the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder managementNodes(AtCustomerCccInfrastructureInfrastructureNetworkConfigurationManagementNodeArgs... managementNodes) {
            return managementNodes(List.of(managementNodes));
        }

        /**
         * @param mgmtVipHostname The hostname corresponding to the virtual IP (VIP) address of the management nodes.
         * 
         * @return builder
         * 
         */
        public Builder mgmtVipHostname(@Nullable Output<String> mgmtVipHostname) {
            $.mgmtVipHostname = mgmtVipHostname;
            return this;
        }

        /**
         * @param mgmtVipHostname The hostname corresponding to the virtual IP (VIP) address of the management nodes.
         * 
         * @return builder
         * 
         */
        public Builder mgmtVipHostname(String mgmtVipHostname) {
            return mgmtVipHostname(Output.of(mgmtVipHostname));
        }

        /**
         * @param mgmtVipIp The IP address used as the virtual IP (VIP) address of the management nodes.
         * 
         * @return builder
         * 
         */
        public Builder mgmtVipIp(@Nullable Output<String> mgmtVipIp) {
            $.mgmtVipIp = mgmtVipIp;
            return this;
        }

        /**
         * @param mgmtVipIp The IP address used as the virtual IP (VIP) address of the management nodes.
         * 
         * @return builder
         * 
         */
        public Builder mgmtVipIp(String mgmtVipIp) {
            return mgmtVipIp(Output.of(mgmtVipIp));
        }

        /**
         * @param spineIps Addresses of the network spine switches.
         * 
         * @return builder
         * 
         */
        public Builder spineIps(@Nullable Output<List<String>> spineIps) {
            $.spineIps = spineIps;
            return this;
        }

        /**
         * @param spineIps Addresses of the network spine switches.
         * 
         * @return builder
         * 
         */
        public Builder spineIps(List<String> spineIps) {
            return spineIps(Output.of(spineIps));
        }

        /**
         * @param spineIps Addresses of the network spine switches.
         * 
         * @return builder
         * 
         */
        public Builder spineIps(String... spineIps) {
            return spineIps(List.of(spineIps));
        }

        /**
         * @param spineVip The spine switch public virtual IP (VIP). Traffic routed to the Compute Cloud{@literal @}Customer infrastructure and  and virtual cloud networks (VCNs) should have this address as next hop.
         * 
         * @return builder
         * 
         */
        public Builder spineVip(@Nullable Output<String> spineVip) {
            $.spineVip = spineVip;
            return this;
        }

        /**
         * @param spineVip The spine switch public virtual IP (VIP). Traffic routed to the Compute Cloud{@literal @}Customer infrastructure and  and virtual cloud networks (VCNs) should have this address as next hop.
         * 
         * @return builder
         * 
         */
        public Builder spineVip(String spineVip) {
            return spineVip(Output.of(spineVip));
        }

        /**
         * @param uplinkDomain Domain name to be used as the base domain for the internal network and by  public facing services.
         * 
         * @return builder
         * 
         */
        public Builder uplinkDomain(@Nullable Output<String> uplinkDomain) {
            $.uplinkDomain = uplinkDomain;
            return this;
        }

        /**
         * @param uplinkDomain Domain name to be used as the base domain for the internal network and by  public facing services.
         * 
         * @return builder
         * 
         */
        public Builder uplinkDomain(String uplinkDomain) {
            return uplinkDomain(Output.of(uplinkDomain));
        }

        /**
         * @param uplinkGatewayIp Uplink gateway in the datacenter network that the Compute Cloud{@literal @}Customer connects to.
         * 
         * @return builder
         * 
         */
        public Builder uplinkGatewayIp(@Nullable Output<String> uplinkGatewayIp) {
            $.uplinkGatewayIp = uplinkGatewayIp;
            return this;
        }

        /**
         * @param uplinkGatewayIp Uplink gateway in the datacenter network that the Compute Cloud{@literal @}Customer connects to.
         * 
         * @return builder
         * 
         */
        public Builder uplinkGatewayIp(String uplinkGatewayIp) {
            return uplinkGatewayIp(Output.of(uplinkGatewayIp));
        }

        /**
         * @param uplinkNetmask Netmask of the subnet that the Compute Cloud{@literal @}Customer infrastructure is connected to.
         * 
         * @return builder
         * 
         */
        public Builder uplinkNetmask(@Nullable Output<String> uplinkNetmask) {
            $.uplinkNetmask = uplinkNetmask;
            return this;
        }

        /**
         * @param uplinkNetmask Netmask of the subnet that the Compute Cloud{@literal @}Customer infrastructure is connected to.
         * 
         * @return builder
         * 
         */
        public Builder uplinkNetmask(String uplinkNetmask) {
            return uplinkNetmask(Output.of(uplinkNetmask));
        }

        /**
         * @param uplinkPortCount Number of uplink ports per spine switch. Connectivity is identical on both spine switches. For example, if input is two 100 gigabyte ports; then port-1 and port-2 on both spines will be configured.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortCount(@Nullable Output<Integer> uplinkPortCount) {
            $.uplinkPortCount = uplinkPortCount;
            return this;
        }

        /**
         * @param uplinkPortCount Number of uplink ports per spine switch. Connectivity is identical on both spine switches. For example, if input is two 100 gigabyte ports; then port-1 and port-2 on both spines will be configured.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortCount(Integer uplinkPortCount) {
            return uplinkPortCount(Output.of(uplinkPortCount));
        }

        /**
         * @param uplinkPortForwardErrorCorrection The port forward error correction (FEC) setting for the uplink port on the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortForwardErrorCorrection(@Nullable Output<String> uplinkPortForwardErrorCorrection) {
            $.uplinkPortForwardErrorCorrection = uplinkPortForwardErrorCorrection;
            return this;
        }

        /**
         * @param uplinkPortForwardErrorCorrection The port forward error correction (FEC) setting for the uplink port on the Compute Cloud{@literal @}Customer infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortForwardErrorCorrection(String uplinkPortForwardErrorCorrection) {
            return uplinkPortForwardErrorCorrection(Output.of(uplinkPortForwardErrorCorrection));
        }

        /**
         * @param uplinkPortSpeedInGbps Uplink port speed defined in gigabytes per second. All uplink ports must have identical speed.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortSpeedInGbps(@Nullable Output<Integer> uplinkPortSpeedInGbps) {
            $.uplinkPortSpeedInGbps = uplinkPortSpeedInGbps;
            return this;
        }

        /**
         * @param uplinkPortSpeedInGbps Uplink port speed defined in gigabytes per second. All uplink ports must have identical speed.
         * 
         * @return builder
         * 
         */
        public Builder uplinkPortSpeedInGbps(Integer uplinkPortSpeedInGbps) {
            return uplinkPortSpeedInGbps(Output.of(uplinkPortSpeedInGbps));
        }

        /**
         * @param uplinkVlanMtu The virtual local area network (VLAN) maximum transmission unit (MTU) size for the uplink ports.
         * 
         * @return builder
         * 
         */
        public Builder uplinkVlanMtu(@Nullable Output<Integer> uplinkVlanMtu) {
            $.uplinkVlanMtu = uplinkVlanMtu;
            return this;
        }

        /**
         * @param uplinkVlanMtu The virtual local area network (VLAN) maximum transmission unit (MTU) size for the uplink ports.
         * 
         * @return builder
         * 
         */
        public Builder uplinkVlanMtu(Integer uplinkVlanMtu) {
            return uplinkVlanMtu(Output.of(uplinkVlanMtu));
        }

        public AtCustomerCccInfrastructureInfrastructureNetworkConfigurationArgs build() {
            return $;
        }
    }

}
