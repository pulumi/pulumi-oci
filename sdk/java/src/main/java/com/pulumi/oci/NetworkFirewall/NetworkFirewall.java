// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkFirewall.NetworkFirewallArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallState;
import com.pulumi.oci.NetworkFirewall.outputs.NetworkFirewallNatConfiguration;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Firewall resource in Oracle Cloud Infrastructure Network Firewall service.
 * 
 * Creates a new NetworkFirewall.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewall;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallArgs;
 * import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallNatConfigurationArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testNetworkFirewall = new NetworkFirewall("testNetworkFirewall", NetworkFirewallArgs.builder()
 *             .compartmentId(compartmentId)
 *             .networkFirewallPolicyId(testNetworkFirewallPolicy.id())
 *             .subnetId(testSubnet.id())
 *             .availabilityDomain(networkFirewallAvailabilityDomain)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(networkFirewallDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .ipv4address(networkFirewallIpv4address)
 *             .ipv6address(networkFirewallIpv6address)
 *             .natConfiguration(NetworkFirewallNatConfigurationArgs.builder()
 *                 .mustEnablePrivateNat(networkFirewallNatConfigurationMustEnablePrivateNat)
 *                 .build())
 *             .networkSecurityGroupIds(networkFirewallNetworkSecurityGroupIds)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * NetworkFirewalls can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:NetworkFirewall/networkFirewall:NetworkFirewall test_network_firewall &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkFirewall/networkFirewall:NetworkFirewall")
public class NetworkFirewall extends com.pulumi.resources.CustomResource {
    /**
     * Availability Domain where Network Firewall instance is created. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    @Export(name="availabilityDomain", refs={String.class}, tree="[0]")
    private Output<String> availabilityDomain;

    /**
     * @return Availability Domain where Network Firewall instance is created. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Network Firewall.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Network Firewall.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name for the Network Firewall. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the Network Firewall. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * IPv4 address for the Network Firewall.
     * 
     */
    @Export(name="ipv4address", refs={String.class}, tree="[0]")
    private Output<String> ipv4address;

    /**
     * @return IPv4 address for the Network Firewall.
     * 
     */
    public Output<String> ipv4address() {
        return this.ipv4address;
    }
    /**
     * IPv6 address for the Network Firewall.
     * 
     */
    @Export(name="ipv6address", refs={String.class}, tree="[0]")
    private Output<String> ipv6address;

    /**
     * @return IPv6 address for the Network Firewall.
     * 
     */
    public Output<String> ipv6address() {
        return this.ipv6address;
    }
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;FAILED&#39; state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;FAILED&#39; state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) Nat Configuration request to use Nat feature on firewall.
     * 
     */
    @Export(name="natConfiguration", refs={NetworkFirewallNatConfiguration.class}, tree="[0]")
    private Output<NetworkFirewallNatConfiguration> natConfiguration;

    /**
     * @return (Updatable) Nat Configuration request to use Nat feature on firewall.
     * 
     */
    public Output<NetworkFirewallNatConfiguration> natConfiguration() {
        return this.natConfiguration;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall Policy.
     * 
     */
    @Export(name="networkFirewallPolicyId", refs={String.class}, tree="[0]")
    private Output<String> networkFirewallPolicyId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall Policy.
     * 
     */
    public Output<String> networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * (Updatable) An array of network security groups [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the Network Firewall.
     * 
     */
    @Export(name="networkSecurityGroupIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> networkSecurityGroupIds;

    /**
     * @return (Updatable) An array of network security groups [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the Network Firewall.
     * 
     */
    public Output<List<String>> networkSecurityGroupIds() {
        return this.networkSecurityGroupIds;
    }
    /**
     * The current state of the Network Firewall.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Network Firewall.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the Network Firewall.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="subnetId", refs={String.class}, tree="[0]")
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the Network Firewall.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time at which the Network Firewall was created in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time at which the Network Firewall was created in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time at which the Network Firewall was updated in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time at which the Network Firewall was updated in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkFirewall(java.lang.String name) {
        this(name, NetworkFirewallArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkFirewall(java.lang.String name, NetworkFirewallArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkFirewall(java.lang.String name, NetworkFirewallArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewall:NetworkFirewall", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private NetworkFirewall(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewall:NetworkFirewall", name, state, makeResourceOptions(options, id), false);
    }

    private static NetworkFirewallArgs makeArgs(NetworkFirewallArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? NetworkFirewallArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static NetworkFirewall get(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkFirewall(name, id, state, options);
    }
}
