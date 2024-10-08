// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyAddressListArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyAddressListState;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Firewall Policy Address List resource in Oracle Cloud Infrastructure Network Firewall service.
 * 
 * Creates a new Address List for the Network Firewall Policy.
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
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyAddressList;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyAddressListArgs;
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
 *         var testNetworkFirewallPolicyAddressList = new NetworkFirewallPolicyAddressList("testNetworkFirewallPolicyAddressList", NetworkFirewallPolicyAddressListArgs.builder()
 *             .name(networkFirewallPolicyAddressListName)
 *             .networkFirewallPolicyId(testNetworkFirewallPolicy.id())
 *             .type(networkFirewallPolicyAddressListType)
 *             .addresses(networkFirewallPolicyAddressListAddresses)
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
 * NetworkFirewallPolicyAddressLists can be imported using the `name`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:NetworkFirewall/networkFirewallPolicyAddressList:NetworkFirewallPolicyAddressList test_network_firewall_policy_address_list &#34;networkFirewallPolicies/{networkFirewallPolicyId}/addressLists/{addressListName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkFirewall/networkFirewallPolicyAddressList:NetworkFirewallPolicyAddressList")
public class NetworkFirewallPolicyAddressList extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) List of addresses.
     * 
     */
    @Export(name="addresses", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> addresses;

    /**
     * @return (Updatable) List of addresses.
     * 
     */
    public Output<List<String>> addresses() {
        return this.addresses;
    }
    /**
     * Unique name to identify the group of addresses to be used in the policy rules.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Unique name to identify the group of addresses to be used in the policy rules.
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
     * OCID of the Network Firewall Policy this Address List belongs to.
     * 
     */
    @Export(name="parentResourceId", refs={String.class}, tree="[0]")
    private Output<String> parentResourceId;

    /**
     * @return OCID of the Network Firewall Policy this Address List belongs to.
     * 
     */
    public Output<String> parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * Count of total addresses in the AddressList
     * 
     */
    @Export(name="totalAddresses", refs={Integer.class}, tree="[0]")
    private Output<Integer> totalAddresses;

    /**
     * @return Count of total addresses in the AddressList
     * 
     */
    public Output<Integer> totalAddresses() {
        return this.totalAddresses;
    }
    /**
     * Type of address List. The accepted values are - * FQDN * IP
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return Type of address List. The accepted values are - * FQDN * IP
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkFirewallPolicyAddressList(java.lang.String name) {
        this(name, NetworkFirewallPolicyAddressListArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkFirewallPolicyAddressList(java.lang.String name, NetworkFirewallPolicyAddressListArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkFirewallPolicyAddressList(java.lang.String name, NetworkFirewallPolicyAddressListArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyAddressList:NetworkFirewallPolicyAddressList", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private NetworkFirewallPolicyAddressList(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallPolicyAddressListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyAddressList:NetworkFirewallPolicyAddressList", name, state, makeResourceOptions(options, id), false);
    }

    private static NetworkFirewallPolicyAddressListArgs makeArgs(NetworkFirewallPolicyAddressListArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? NetworkFirewallPolicyAddressListArgs.Empty : args;
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
    public static NetworkFirewallPolicyAddressList get(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkFirewallPolicyAddressListState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkFirewallPolicyAddressList(name, id, state, options);
    }
}
