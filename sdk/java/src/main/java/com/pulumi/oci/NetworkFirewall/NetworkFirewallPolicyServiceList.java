// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyServiceListArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyServiceListState;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Firewall Policy Service List resource in Oracle Cloud Infrastructure Network Firewall service.
 * 
 * Creates a new ServiceList for the Network Firewall Policy.
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
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyServiceList;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyServiceListArgs;
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
 *         var testNetworkFirewallPolicyServiceList = new NetworkFirewallPolicyServiceList("testNetworkFirewallPolicyServiceList", NetworkFirewallPolicyServiceListArgs.builder()
 *             .name(networkFirewallPolicyServiceListName)
 *             .networkFirewallPolicyId(testNetworkFirewallPolicy.id())
 *             .services(networkFirewallPolicyServiceListServices)
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
 * NetworkFirewallPolicyServiceLists can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList test_network_firewall_policy_service_list &#34;networkFirewallPolicies/{networkFirewallPolicyId}/serviceLists/{serviceListName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList")
public class NetworkFirewallPolicyServiceList extends com.pulumi.resources.CustomResource {
    /**
     * Name of the service Group.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Name of the service Group.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Export(name="networkFirewallPolicyId", refs={String.class}, tree="[0]")
    private Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Output<String> networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * OCID of the Network Firewall Policy this serviceList belongs to.
     * 
     */
    @Export(name="parentResourceId", refs={String.class}, tree="[0]")
    private Output<String> parentResourceId;

    /**
     * @return OCID of the Network Firewall Policy this serviceList belongs to.
     * 
     */
    public Output<String> parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * (Updatable) Collection of service names. The services referenced in the service list must already be present in the policy before being used in the service list.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="services", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> services;

    /**
     * @return (Updatable) Collection of service names. The services referenced in the service list must already be present in the policy before being used in the service list.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> services() {
        return this.services;
    }
    /**
     * Count of total services in the given service List.
     * 
     */
    @Export(name="totalServices", refs={Integer.class}, tree="[0]")
    private Output<Integer> totalServices;

    /**
     * @return Count of total services in the given service List.
     * 
     */
    public Output<Integer> totalServices() {
        return this.totalServices;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkFirewallPolicyServiceList(java.lang.String name) {
        this(name, NetworkFirewallPolicyServiceListArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkFirewallPolicyServiceList(java.lang.String name, NetworkFirewallPolicyServiceListArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkFirewallPolicyServiceList(java.lang.String name, NetworkFirewallPolicyServiceListArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private NetworkFirewallPolicyServiceList(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallPolicyServiceListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyServiceList:NetworkFirewallPolicyServiceList", name, state, makeResourceOptions(options, id), false);
    }

    private static NetworkFirewallPolicyServiceListArgs makeArgs(NetworkFirewallPolicyServiceListArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? NetworkFirewallPolicyServiceListArgs.Empty : args;
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
    public static NetworkFirewallPolicyServiceList get(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallPolicyServiceListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkFirewallPolicyServiceList(name, id, state, options);
    }
}
