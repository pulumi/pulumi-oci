// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service.
 *
 * Creates a new resolver endpoint in the same compartment as the resolver.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResolverEndpoint = new oci.dns.ResolverEndpoint("test_resolver_endpoint", {
 *     isForwarding: resolverEndpointIsForwarding,
 *     isListening: resolverEndpointIsListening,
 *     name: resolverEndpointName,
 *     resolverId: testResolver.id,
 *     subnetId: testSubnet.id,
 *     scope: "PRIVATE",
 *     endpointType: resolverEndpointEndpointType,
 *     forwardingAddress: resolverEndpointForwardingAddress,
 *     listeningAddress: resolverEndpointListeningAddress,
 *     nsgIds: resolverEndpointNsgIds,
 * });
 * ```
 *
 * ## Import
 *
 * For legacy ResolverEndpoints created without `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{resolverEndpointName}"
 * ```
 * For ResolverEndpoints created using `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{name}/scope/{scope}"
 * ```
 */
export class ResolverEndpoint extends pulumi.CustomResource {
    /**
     * Get an existing ResolverEndpoint resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ResolverEndpointState, opts?: pulumi.CustomResourceOptions): ResolverEndpoint {
        return new ResolverEndpoint(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Dns/resolverEndpoint:ResolverEndpoint';

    /**
     * Returns true if the given object is an instance of ResolverEndpoint.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ResolverEndpoint {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ResolverEndpoint.__pulumiType;
    }

    /**
     * The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
     */
    public readonly endpointType!: pulumi.Output<string>;
    /**
     * An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
     */
    public readonly forwardingAddress!: pulumi.Output<string>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
     */
    public readonly isForwarding!: pulumi.Output<boolean>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for listening.
     */
    public readonly isListening!: pulumi.Output<boolean>;
    /**
     * An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
     */
    public readonly listeningAddress!: pulumi.Output<string>;
    /**
     * The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
     */
    public readonly nsgIds!: pulumi.Output<string[] | undefined>;
    /**
     * The OCID of the target resolver.
     */
    public readonly resolverId!: pulumi.Output<string>;
    /**
     * Value must be `PRIVATE` when creating private name resolver endpoints.
     */
    public readonly scope!: pulumi.Output<string | undefined>;
    /**
     * The canonical absolute URL of the resource.
     */
    public /*out*/ readonly self!: pulumi.Output<string>;
    /**
     * The current state of the resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ResolverEndpoint resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ResolverEndpointArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ResolverEndpointArgs | ResolverEndpointState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ResolverEndpointState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["endpointType"] = state ? state.endpointType : undefined;
            resourceInputs["forwardingAddress"] = state ? state.forwardingAddress : undefined;
            resourceInputs["isForwarding"] = state ? state.isForwarding : undefined;
            resourceInputs["isListening"] = state ? state.isListening : undefined;
            resourceInputs["listeningAddress"] = state ? state.listeningAddress : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["resolverId"] = state ? state.resolverId : undefined;
            resourceInputs["scope"] = state ? state.scope : undefined;
            resourceInputs["self"] = state ? state.self : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ResolverEndpointArgs | undefined;
            if ((!args || args.isForwarding === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isForwarding'");
            }
            if ((!args || args.isListening === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isListening'");
            }
            if ((!args || args.resolverId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resolverId'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["endpointType"] = args ? args.endpointType : undefined;
            resourceInputs["forwardingAddress"] = args ? args.forwardingAddress : undefined;
            resourceInputs["isForwarding"] = args ? args.isForwarding : undefined;
            resourceInputs["isListening"] = args ? args.isListening : undefined;
            resourceInputs["listeningAddress"] = args ? args.listeningAddress : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["resolverId"] = args ? args.resolverId : undefined;
            resourceInputs["scope"] = args ? args.scope : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["self"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ResolverEndpoint.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ResolverEndpoint resources.
 */
export interface ResolverEndpointState {
    /**
     * The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
     */
    endpointType?: pulumi.Input<string>;
    /**
     * An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
     */
    forwardingAddress?: pulumi.Input<string>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
     */
    isForwarding?: pulumi.Input<boolean>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for listening.
     */
    isListening?: pulumi.Input<boolean>;
    /**
     * An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
     */
    listeningAddress?: pulumi.Input<string>;
    /**
     * The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
     */
    name?: pulumi.Input<string>;
    /**
     * An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the target resolver.
     */
    resolverId?: pulumi.Input<string>;
    /**
     * Value must be `PRIVATE` when creating private name resolver endpoints.
     */
    scope?: pulumi.Input<string>;
    /**
     * The canonical absolute URL of the resource.
     */
    self?: pulumi.Input<string>;
    /**
     * The current state of the resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ResolverEndpoint resource.
 */
export interface ResolverEndpointArgs {
    /**
     * (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
     */
    endpointType?: pulumi.Input<string>;
    /**
     * An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
     */
    forwardingAddress?: pulumi.Input<string>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
     */
    isForwarding: pulumi.Input<boolean>;
    /**
     * A Boolean flag indicating whether or not the resolver endpoint is for listening.
     */
    isListening: pulumi.Input<boolean>;
    /**
     * An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
     */
    listeningAddress?: pulumi.Input<string>;
    /**
     * The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
     */
    name?: pulumi.Input<string>;
    /**
     * An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the target resolver.
     */
    resolverId: pulumi.Input<string>;
    /**
     * Value must be `PRIVATE` when creating private name resolver endpoints.
     */
    scope?: pulumi.Input<string>;
    /**
     * The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId: pulumi.Input<string>;
}
