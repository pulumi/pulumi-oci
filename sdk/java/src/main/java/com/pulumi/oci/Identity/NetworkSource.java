// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.NetworkSourceArgs;
import com.pulumi.oci.Identity.inputs.NetworkSourceState;
import com.pulumi.oci.Identity.outputs.NetworkSourceVirtualSourceList;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Source resource in Oracle Cloud Infrastructure Identity service.
 * 
 * Creates a new network source in your tenancy.
 * 
 * You must specify your tenancy&#39;s OCID as the compartment ID in the request object (remember that the tenancy
 * is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
 * reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
 * reside within compartments inside the tenancy. For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 * 
 * You must also specify a *name* for the network source, which must be unique across all network sources in your
 * tenancy, and cannot be changed.
 * You can use this name or the OCID when writing policies that apply to the network source. For more information
 * about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).
 * 
 * You must also specify a *description* for the network source (although it can be an empty string). It does not
 * have to be unique, and you can change it anytime with [UpdateNetworkSource](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/NetworkSource/UpdateNetworkSource).
 * After your network resource is created, you can use it in policy to restrict access to only requests made from an allowed
 * IP address specified in your network source. For more information, see [Managing Network Sources](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingnetworksources.htm).
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
 * import com.pulumi.oci.Identity.NetworkSource;
 * import com.pulumi.oci.Identity.NetworkSourceArgs;
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
 *         var testNetworkSource = new NetworkSource("testNetworkSource", NetworkSourceArgs.builder()
 *             .compartmentId(tenancyOcid)
 *             .description(networkSourceDescription)
 *             .name(networkSourceName)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .publicSourceLists(networkSourcePublicSourceList)
 *             .services(networkSourceServices)
 *             .virtualSourceLists(networkSourceVirtualSourceList)
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
 * NetworkSources can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Identity/networkSource:NetworkSource test_network_source &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/networkSource:NetworkSource")
public class NetworkSource extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the tenancy (root compartment) containing the network source object.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy (root compartment) containing the network source object.
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
     * (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Output<String> description() {
        return this.description;
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
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Export(name="inactiveState", refs={String.class}, tree="[0]")
    private Output<String> inactiveState;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Output<String> inactiveState() {
        return this.inactiveState;
    }
    /**
     * The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    @Export(name="publicSourceLists", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> publicSourceLists;

    /**
     * @return (Updatable) A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    public Output<List<String>> publicSourceLists() {
        return this.publicSourceLists;
    }
    /**
     * (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    @Export(name="services", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> services;

    /**
     * @return (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    public Output<List<String>> services() {
        return this.services;
    }
    /**
     * The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="virtualSourceLists", refs={List.class,NetworkSourceVirtualSourceList.class}, tree="[0,1]")
    private Output<List<NetworkSourceVirtualSourceList>> virtualSourceLists;

    /**
     * @return (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<NetworkSourceVirtualSourceList>> virtualSourceLists() {
        return this.virtualSourceLists;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkSource(java.lang.String name) {
        this(name, NetworkSourceArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkSource(java.lang.String name, NetworkSourceArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkSource(java.lang.String name, NetworkSourceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/networkSource:NetworkSource", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private NetworkSource(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkSourceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/networkSource:NetworkSource", name, state, makeResourceOptions(options, id), false);
    }

    private static NetworkSourceArgs makeArgs(NetworkSourceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? NetworkSourceArgs.Empty : args;
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
    public static NetworkSource get(java.lang.String name, Output<java.lang.String> id, @Nullable NetworkSourceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkSource(name, id, state, options);
    }
}
