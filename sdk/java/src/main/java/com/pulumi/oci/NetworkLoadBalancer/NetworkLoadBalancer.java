// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkLoadBalancer.NetworkLoadBalancerArgs;
import com.pulumi.oci.NetworkLoadBalancer.inputs.NetworkLoadBalancerState;
import com.pulumi.oci.NetworkLoadBalancer.outputs.NetworkLoadBalancerIpAddress;
import com.pulumi.oci.NetworkLoadBalancer.outputs.NetworkLoadBalancerReservedIp;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
 * 
 * Creates a network load balancer.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * NetworkLoadBalancers can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer test_network_load_balancer &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer")
public class NetworkLoadBalancer extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
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
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Network load balancer identifier, which can be renamed.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
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
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * An array of IP addresses.
     * 
     */
    @Export(name="ipAddresses", type=List.class, parameters={NetworkLoadBalancerIpAddress.class})
    private Output<List<NetworkLoadBalancerIpAddress>> ipAddresses;

    /**
     * @return An array of IP addresses.
     * 
     */
    public Output<List<NetworkLoadBalancerIpAddress>> ipAddresses() {
        return this.ipAddresses;
    }
    /**
     * (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     * 
     */
    @Export(name="isPreserveSourceDestination", type=Boolean.class, parameters={})
    private Output<Boolean> isPreserveSourceDestination;

    /**
     * @return (Updatable) This parameter can be enabled only if backends are compute OCIDs. When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC, and packets are sent to the backend with the entire IP header intact.
     * 
     */
    public Output<Boolean> isPreserveSourceDestination() {
        return this.isPreserveSourceDestination;
    }
    /**
     * Whether the network load balancer has a virtual cloud network-local (private) IP address.
     * 
     */
    @Export(name="isPrivate", type=Boolean.class, parameters={})
    private Output<Boolean> isPrivate;

    /**
     * @return Whether the network load balancer has a virtual cloud network-local (private) IP address.
     * 
     */
    public Output<Boolean> isPrivate() {
        return this.isPrivate;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     * 
     */
    @Export(name="networkSecurityGroupIds", type=List.class, parameters={String.class})
    private Output</* @Nullable */ List<String>> networkSecurityGroupIds;

    /**
     * @return (Updatable) An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
     * 
     */
    public Output<Optional<List<String>>> networkSecurityGroupIds() {
        return Codegen.optional(this.networkSecurityGroupIds);
    }
    /**
     * (Updatable) IP version associated with the NLB.
     * 
     */
    @Export(name="nlbIpVersion", type=String.class, parameters={})
    private Output<String> nlbIpVersion;

    /**
     * @return (Updatable) IP version associated with the NLB.
     * 
     */
    public Output<String> nlbIpVersion() {
        return this.nlbIpVersion;
    }
    /**
     * An array of reserved Ips.
     * 
     */
    @Export(name="reservedIps", type=List.class, parameters={NetworkLoadBalancerReservedIp.class})
    private Output<List<NetworkLoadBalancerReservedIp>> reservedIps;

    /**
     * @return An array of reserved Ips.
     * 
     */
    public Output<List<NetworkLoadBalancerReservedIp>> reservedIps() {
        return this.reservedIps;
    }
    /**
     * The current state of the network load balancer.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the network load balancer.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="subnetId", type=String.class, parameters={})
    private Output<String> subnetId;

    /**
     * @return The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * Key-value pair representing system tags&#39; keys and values scoped to a namespace. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Key-value pair representing system tags&#39; keys and values scoped to a namespace. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkLoadBalancer(String name) {
        this(name, NetworkLoadBalancerArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkLoadBalancer(String name, NetworkLoadBalancerArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkLoadBalancer(String name, NetworkLoadBalancerArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer", name, args == null ? NetworkLoadBalancerArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private NetworkLoadBalancer(String name, Output<String> id, @Nullable NetworkLoadBalancerState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkLoadBalancer/networkLoadBalancer:NetworkLoadBalancer", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static NetworkLoadBalancer get(String name, Output<String> id, @Nullable NetworkLoadBalancerState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkLoadBalancer(name, id, state, options);
    }
}
