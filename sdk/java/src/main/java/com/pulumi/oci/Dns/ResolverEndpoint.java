// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Dns.ResolverEndpointArgs;
import com.pulumi.oci.Dns.inputs.ResolverEndpointState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service.
 * 
 * Creates a new resolver endpoint. Requires a `PRIVATE` scope query parameter.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * For legacy ResolverEndpoints created without `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint &#34;resolverId/{resolverId}/name/{resolverEndpointName}&#34;
 * ```
 * 
 *  For ResolverEndpoints created using `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint &#34;resolverId/{resolverId}/name/{name}/scope/{scope}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Dns/resolverEndpoint:ResolverEndpoint")
public class ResolverEndpoint extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver&#39;s compartment is changed.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver&#39;s compartment is changed.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
     * 
     */
    @Export(name="endpointType", type=String.class, parameters={})
    private Output<String> endpointType;

    /**
     * @return (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
     * 
     */
    public Output<String> endpointType() {
        return this.endpointType;
    }
    /**
     * An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
     * 
     */
    @Export(name="forwardingAddress", type=String.class, parameters={})
    private Output<String> forwardingAddress;

    /**
     * @return An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
     * 
     */
    public Output<String> forwardingAddress() {
        return this.forwardingAddress;
    }
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
     * 
     */
    @Export(name="isForwarding", type=Boolean.class, parameters={})
    private Output<Boolean> isForwarding;

    /**
     * @return A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
     * 
     */
    public Output<Boolean> isForwarding() {
        return this.isForwarding;
    }
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for listening.
     * 
     */
    @Export(name="isListening", type=Boolean.class, parameters={})
    private Output<Boolean> isListening;

    /**
     * @return A Boolean flag indicating whether or not the resolver endpoint is for listening.
     * 
     */
    public Output<Boolean> isListening() {
        return this.isListening;
    }
    /**
     * An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
     * 
     */
    @Export(name="listeningAddress", type=String.class, parameters={})
    private Output<String> listeningAddress;

    /**
     * @return An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
     * 
     */
    public Output<String> listeningAddress() {
        return this.listeningAddress;
    }
    /**
     * The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
     * 
     */
    @Export(name="nsgIds", type=List.class, parameters={String.class})
    private Output</* @Nullable */ List<String>> nsgIds;

    /**
     * @return An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
     * 
     */
    public Output<Optional<List<String>>> nsgIds() {
        return Codegen.optional(this.nsgIds);
    }
    /**
     * The OCID of the target resolver.
     * 
     */
    @Export(name="resolverId", type=String.class, parameters={})
    private Output<String> resolverId;

    /**
     * @return The OCID of the target resolver.
     * 
     */
    public Output<String> resolverId() {
        return this.resolverId;
    }
    /**
     * Value must be `PRIVATE` when creating private name resolver endpoints.
     * 
     */
    @Export(name="scope", type=String.class, parameters={})
    private Output<String> scope;

    /**
     * @return Value must be `PRIVATE` when creating private name resolver endpoints.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }
    /**
     * The canonical absolute URL of the resource.
     * 
     */
    @Export(name="self", type=String.class, parameters={})
    private Output<String> self;

    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public Output<String> self() {
        return this.self;
    }
    /**
     * The current state of the resource.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
     * 
     */
    @Export(name="subnetId", type=String.class, parameters={})
    private Output<String> subnetId;

    /**
     * @return The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was last updated in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was last updated in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ResolverEndpoint(String name) {
        this(name, ResolverEndpointArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ResolverEndpoint(String name, ResolverEndpointArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ResolverEndpoint(String name, ResolverEndpointArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/resolverEndpoint:ResolverEndpoint", name, args == null ? ResolverEndpointArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ResolverEndpoint(String name, Output<String> id, @Nullable ResolverEndpointState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/resolverEndpoint:ResolverEndpoint", name, state, makeResourceOptions(options, id));
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
    public static ResolverEndpoint get(String name, Output<String> id, @Nullable ResolverEndpointState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ResolverEndpoint(name, id, state, options);
    }
}
