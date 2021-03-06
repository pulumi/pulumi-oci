// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkLoadBalancer.inputs.NetworkLoadBalancerReservedIpArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkLoadBalancerArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkLoadBalancerArgs Empty = new NetworkLoadBalancerArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Network load balancer identifier, which can be renamed.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Network load balancer identifier, which can be renamed.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     * 
     */
    @Import(name="isPreserveSourceDestination")
    private @Nullable Output<Boolean> isPreserveSourceDestination;

    /**
     * @return (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     * 
     */
    public Optional<Output<Boolean>> isPreserveSourceDestination() {
        return Optional.ofNullable(this.isPreserveSourceDestination);
    }

    /**
     * Whether the network load balancer has a virtual cloud network-local (private) IP address.
     * 
     */
    @Import(name="isPrivate")
    private @Nullable Output<Boolean> isPrivate;

    /**
     * @return Whether the network load balancer has a virtual cloud network-local (private) IP address.
     * 
     */
    public Optional<Output<Boolean>> isPrivate() {
        return Optional.ofNullable(this.isPrivate);
    }

    /**
     * (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     * 
     */
    @Import(name="networkSecurityGroupIds")
    private @Nullable Output<List<String>> networkSecurityGroupIds;

    /**
     * @return (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     * 
     */
    public Optional<Output<List<String>>> networkSecurityGroupIds() {
        return Optional.ofNullable(this.networkSecurityGroupIds);
    }

    /**
     * (Updatable) IP version associated with the NLB.
     * 
     */
    @Import(name="nlbIpVersion")
    private @Nullable Output<String> nlbIpVersion;

    /**
     * @return (Updatable) IP version associated with the NLB.
     * 
     */
    public Optional<Output<String>> nlbIpVersion() {
        return Optional.ofNullable(this.nlbIpVersion);
    }

    /**
     * An array of reserved Ips.
     * 
     */
    @Import(name="reservedIps")
    private @Nullable Output<List<NetworkLoadBalancerReservedIpArgs>> reservedIps;

    /**
     * @return An array of reserved Ips.
     * 
     */
    public Optional<Output<List<NetworkLoadBalancerReservedIpArgs>>> reservedIps() {
        return Optional.ofNullable(this.reservedIps);
    }

    /**
     * The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private NetworkLoadBalancerArgs() {}

    private NetworkLoadBalancerArgs(NetworkLoadBalancerArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isPreserveSourceDestination = $.isPreserveSourceDestination;
        this.isPrivate = $.isPrivate;
        this.networkSecurityGroupIds = $.networkSecurityGroupIds;
        this.nlbIpVersion = $.nlbIpVersion;
        this.reservedIps = $.reservedIps;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkLoadBalancerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkLoadBalancerArgs $;

        public Builder() {
            $ = new NetworkLoadBalancerArgs();
        }

        public Builder(NetworkLoadBalancerArgs defaults) {
            $ = new NetworkLoadBalancerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Network load balancer identifier, which can be renamed.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Network load balancer identifier, which can be renamed.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isPreserveSourceDestination (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
         * 
         * @return builder
         * 
         */
        public Builder isPreserveSourceDestination(@Nullable Output<Boolean> isPreserveSourceDestination) {
            $.isPreserveSourceDestination = isPreserveSourceDestination;
            return this;
        }

        /**
         * @param isPreserveSourceDestination (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
         * 
         * @return builder
         * 
         */
        public Builder isPreserveSourceDestination(Boolean isPreserveSourceDestination) {
            return isPreserveSourceDestination(Output.of(isPreserveSourceDestination));
        }

        /**
         * @param isPrivate Whether the network load balancer has a virtual cloud network-local (private) IP address.
         * 
         * @return builder
         * 
         */
        public Builder isPrivate(@Nullable Output<Boolean> isPrivate) {
            $.isPrivate = isPrivate;
            return this;
        }

        /**
         * @param isPrivate Whether the network load balancer has a virtual cloud network-local (private) IP address.
         * 
         * @return builder
         * 
         */
        public Builder isPrivate(Boolean isPrivate) {
            return isPrivate(Output.of(isPrivate));
        }

        /**
         * @param networkSecurityGroupIds (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
         * 
         * @return builder
         * 
         */
        public Builder networkSecurityGroupIds(@Nullable Output<List<String>> networkSecurityGroupIds) {
            $.networkSecurityGroupIds = networkSecurityGroupIds;
            return this;
        }

        /**
         * @param networkSecurityGroupIds (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
         * 
         * @return builder
         * 
         */
        public Builder networkSecurityGroupIds(List<String> networkSecurityGroupIds) {
            return networkSecurityGroupIds(Output.of(networkSecurityGroupIds));
        }

        /**
         * @param networkSecurityGroupIds (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
         * 
         * @return builder
         * 
         */
        public Builder networkSecurityGroupIds(String... networkSecurityGroupIds) {
            return networkSecurityGroupIds(List.of(networkSecurityGroupIds));
        }

        /**
         * @param nlbIpVersion (Updatable) IP version associated with the NLB.
         * 
         * @return builder
         * 
         */
        public Builder nlbIpVersion(@Nullable Output<String> nlbIpVersion) {
            $.nlbIpVersion = nlbIpVersion;
            return this;
        }

        /**
         * @param nlbIpVersion (Updatable) IP version associated with the NLB.
         * 
         * @return builder
         * 
         */
        public Builder nlbIpVersion(String nlbIpVersion) {
            return nlbIpVersion(Output.of(nlbIpVersion));
        }

        /**
         * @param reservedIps An array of reserved Ips.
         * 
         * @return builder
         * 
         */
        public Builder reservedIps(@Nullable Output<List<NetworkLoadBalancerReservedIpArgs>> reservedIps) {
            $.reservedIps = reservedIps;
            return this;
        }

        /**
         * @param reservedIps An array of reserved Ips.
         * 
         * @return builder
         * 
         */
        public Builder reservedIps(List<NetworkLoadBalancerReservedIpArgs> reservedIps) {
            return reservedIps(Output.of(reservedIps));
        }

        /**
         * @param reservedIps An array of reserved Ips.
         * 
         * @return builder
         * 
         */
        public Builder reservedIps(NetworkLoadBalancerReservedIpArgs... reservedIps) {
            return reservedIps(List.of(reservedIps));
        }

        /**
         * @param subnetId The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public NetworkLoadBalancerArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.subnetId = Objects.requireNonNull($.subnetId, "expected parameter 'subnetId' to be non-null");
            return $;
        }
    }

}
