// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Bastion.BastionArgs;
import com.pulumi.oci.Bastion.inputs.BastionState;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Bastion resource in Oracle Cloud Infrastructure Bastion service.
 * 
 * Creates a new bastion. A bastion provides secured, public access to target resources in the cloud that you cannot otherwise reach from the internet. A bastion resides in a public subnet and establishes the network infrastructure needed to connect a user to a target resource in a private subnet.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Bastion.Bastion;
 * import com.pulumi.oci.Bastion.BastionArgs;
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
 *         var testBastion = new Bastion(&#34;testBastion&#34;, BastionArgs.builder()        
 *             .bastionType(var_.bastion_bastion_type())
 *             .compartmentId(var_.compartment_id())
 *             .targetSubnetId(oci_core_subnet.test_subnet().id())
 *             .clientCidrBlockAllowLists(var_.bastion_client_cidr_block_allow_list())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .maxSessionTtlInSeconds(var_.bastion_max_session_ttl_in_seconds())
 *             .phoneBookEntry(var_.bastion_phone_book_entry())
 *             .staticJumpHostIpAddresses(var_.bastion_static_jump_host_ip_addresses())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Bastions can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Bastion/bastion:Bastion test_bastion &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Bastion/bastion:Bastion")
public class Bastion extends com.pulumi.resources.CustomResource {
    /**
     * The type of bastion. Use `standard`.
     * 
     */
    @Export(name="bastionType", type=String.class, parameters={})
    private Output<String> bastionType;

    /**
     * @return The type of bastion. Use `standard`.
     * 
     */
    public Output<String> bastionType() {
        return this.bastionType;
    }
    /**
     * (Updatable) A list of address ranges in CIDR notation that you want to allow to connect to sessions hosted by this bastion.
     * 
     */
    @Export(name="clientCidrBlockAllowLists", type=List.class, parameters={String.class})
    private Output<List<String>> clientCidrBlockAllowLists;

    /**
     * @return (Updatable) A list of address ranges in CIDR notation that you want to allow to connect to sessions hosted by this bastion.
     * 
     */
    public Output<List<String>> clientCidrBlockAllowLists() {
        return this.clientCidrBlockAllowLists;
    }
    /**
     * (Updatable) The unique identifier (OCID) of the compartment where the bastion is located.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The unique identifier (OCID) of the compartment where the bastion is located.
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
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current state in more detail.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The maximum amount of time that any session on the bastion can remain active.
     * 
     */
    @Export(name="maxSessionTtlInSeconds", type=Integer.class, parameters={})
    private Output<Integer> maxSessionTtlInSeconds;

    /**
     * @return (Updatable) The maximum amount of time that any session on the bastion can remain active.
     * 
     */
    public Output<Integer> maxSessionTtlInSeconds() {
        return this.maxSessionTtlInSeconds;
    }
    /**
     * The maximum number of active sessions allowed on the bastion.
     * 
     */
    @Export(name="maxSessionsAllowed", type=Integer.class, parameters={})
    private Output<Integer> maxSessionsAllowed;

    /**
     * @return The maximum number of active sessions allowed on the bastion.
     * 
     */
    public Output<Integer> maxSessionsAllowed() {
        return this.maxSessionsAllowed;
    }
    /**
     * The name of the bastion, which can&#39;t be changed after creation.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return The name of the bastion, which can&#39;t be changed after creation.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The phonebook entry of the customer&#39;s team, which can&#39;t be changed after creation. Not applicable to `standard` bastions.
     * 
     */
    @Export(name="phoneBookEntry", type=String.class, parameters={})
    private Output<String> phoneBookEntry;

    /**
     * @return The phonebook entry of the customer&#39;s team, which can&#39;t be changed after creation. Not applicable to `standard` bastions.
     * 
     */
    public Output<String> phoneBookEntry() {
        return this.phoneBookEntry;
    }
    /**
     * The private IP address of the created private endpoint.
     * 
     */
    @Export(name="privateEndpointIpAddress", type=String.class, parameters={})
    private Output<String> privateEndpointIpAddress;

    /**
     * @return The private IP address of the created private endpoint.
     * 
     */
    public Output<String> privateEndpointIpAddress() {
        return this.privateEndpointIpAddress;
    }
    /**
     * The current state of the bastion.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the bastion.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) A list of IP addresses of the hosts that the bastion has access to. Not applicable to `standard` bastions.
     * 
     */
    @Export(name="staticJumpHostIpAddresses", type=List.class, parameters={String.class})
    private Output<List<String>> staticJumpHostIpAddresses;

    /**
     * @return (Updatable) A list of IP addresses of the hosts that the bastion has access to. Not applicable to `standard` bastions.
     * 
     */
    public Output<List<String>> staticJumpHostIpAddresses() {
        return this.staticJumpHostIpAddresses;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The unique identifier (OCID) of the subnet that the bastion connects to.
     * 
     */
    @Export(name="targetSubnetId", type=String.class, parameters={})
    private Output<String> targetSubnetId;

    /**
     * @return The unique identifier (OCID) of the subnet that the bastion connects to.
     * 
     */
    public Output<String> targetSubnetId() {
        return this.targetSubnetId;
    }
    /**
     * The unique identifier (OCID) of the virtual cloud network (VCN) that the bastion connects to.
     * 
     */
    @Export(name="targetVcnId", type=String.class, parameters={})
    private Output<String> targetVcnId;

    /**
     * @return The unique identifier (OCID) of the virtual cloud network (VCN) that the bastion connects to.
     * 
     */
    public Output<String> targetVcnId() {
        return this.targetVcnId;
    }
    /**
     * The time the bastion was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the bastion was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the bastion was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the bastion was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Bastion(String name) {
        this(name, BastionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Bastion(String name, BastionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Bastion(String name, BastionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Bastion/bastion:Bastion", name, args == null ? BastionArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Bastion(String name, Output<String> id, @Nullable BastionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Bastion/bastion:Bastion", name, state, makeResourceOptions(options, id));
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
    public static Bastion get(String name, Output<String> id, @Nullable BastionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Bastion(name, id, state, options);
    }
}