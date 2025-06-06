// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Path Analyzer Test resource in Oracle Cloud Infrastructure Vn Monitoring service.
 *
 * Creates a new `PathAnalyzerTest` resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPathAnalyzerTest = new oci.vnmonitoring.PathAnalyzerTest("test_path_analyzer_test", {
 *     compartmentId: compartmentId,
 *     destinationEndpoint: {
 *         type: pathAnalyzerTestDestinationEndpointType,
 *         address: pathAnalyzerTestDestinationEndpointAddress,
 *         instanceId: testInstance.id,
 *         listenerId: testListener.id,
 *         loadBalancerId: testLoadBalancer.id,
 *         networkLoadBalancerId: testNetworkLoadBalancer.id,
 *         subnetId: testSubnet.id,
 *         vlanId: testVlan.id,
 *         vnicId: testVnicAttachment.id,
 *     },
 *     protocol: pathAnalyzerTestProtocol,
 *     sourceEndpoint: {
 *         type: pathAnalyzerTestSourceEndpointType,
 *         address: pathAnalyzerTestSourceEndpointAddress,
 *         instanceId: testInstance.id,
 *         listenerId: testListener.id,
 *         loadBalancerId: testLoadBalancer.id,
 *         networkLoadBalancerId: testNetworkLoadBalancer.id,
 *         subnetId: testSubnet.id,
 *         vlanId: testVlan.id,
 *         vnicId: testVnicAttachment.id,
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: pathAnalyzerTestDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     protocolParameters: {
 *         type: pathAnalyzerTestProtocolParametersType,
 *         destinationPort: pathAnalyzerTestProtocolParametersDestinationPort,
 *         icmpCode: pathAnalyzerTestProtocolParametersIcmpCode,
 *         icmpType: pathAnalyzerTestProtocolParametersIcmpType,
 *         sourcePort: pathAnalyzerTestProtocolParametersSourcePort,
 *     },
 *     queryOptions: {
 *         isBiDirectionalAnalysis: pathAnalyzerTestQueryOptionsIsBiDirectionalAnalysis,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * PathAnalyzerTests can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:VnMonitoring/pathAnalyzerTest:PathAnalyzerTest test_path_analyzer_test "id"
 * ```
 */
export class PathAnalyzerTest extends pulumi.CustomResource {
    /**
     * Get an existing PathAnalyzerTest resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PathAnalyzerTestState, opts?: pulumi.CustomResourceOptions): PathAnalyzerTest {
        return new PathAnalyzerTest(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:VnMonitoring/pathAnalyzerTest:PathAnalyzerTest';

    /**
     * Returns true if the given object is an instance of PathAnalyzerTest.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PathAnalyzerTest {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PathAnalyzerTest.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource's compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    public readonly destinationEndpoint!: pulumi.Output<outputs.VnMonitoring.PathAnalyzerTestDestinationEndpoint>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
     */
    public readonly protocol!: pulumi.Output<number>;
    /**
     * (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
     */
    public readonly protocolParameters!: pulumi.Output<outputs.VnMonitoring.PathAnalyzerTestProtocolParameters>;
    /**
     * (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
     */
    public readonly queryOptions!: pulumi.Output<outputs.VnMonitoring.PathAnalyzerTestQueryOptions>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    public readonly sourceEndpoint!: pulumi.Output<outputs.VnMonitoring.PathAnalyzerTestSourceEndpoint>;
    /**
     * The current state of the `PathAnalyzerTest` resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a PathAnalyzerTest resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PathAnalyzerTestArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PathAnalyzerTestArgs | PathAnalyzerTestState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PathAnalyzerTestState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["destinationEndpoint"] = state ? state.destinationEndpoint : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["protocol"] = state ? state.protocol : undefined;
            resourceInputs["protocolParameters"] = state ? state.protocolParameters : undefined;
            resourceInputs["queryOptions"] = state ? state.queryOptions : undefined;
            resourceInputs["sourceEndpoint"] = state ? state.sourceEndpoint : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as PathAnalyzerTestArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.destinationEndpoint === undefined) && !opts.urn) {
                throw new Error("Missing required property 'destinationEndpoint'");
            }
            if ((!args || args.protocol === undefined) && !opts.urn) {
                throw new Error("Missing required property 'protocol'");
            }
            if ((!args || args.sourceEndpoint === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceEndpoint'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["destinationEndpoint"] = args ? args.destinationEndpoint : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["protocol"] = args ? args.protocol : undefined;
            resourceInputs["protocolParameters"] = args ? args.protocolParameters : undefined;
            resourceInputs["queryOptions"] = args ? args.queryOptions : undefined;
            resourceInputs["sourceEndpoint"] = args ? args.sourceEndpoint : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(PathAnalyzerTest.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PathAnalyzerTest resources.
 */
export interface PathAnalyzerTestState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource's compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    destinationEndpoint?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestDestinationEndpoint>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
     */
    protocol?: pulumi.Input<number>;
    /**
     * (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
     */
    protocolParameters?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestProtocolParameters>;
    /**
     * (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
     */
    queryOptions?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestQueryOptions>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    sourceEndpoint?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestSourceEndpoint>;
    /**
     * The current state of the `PathAnalyzerTest` resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PathAnalyzerTest resource.
 */
export interface PathAnalyzerTestArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the `PathAnalyzerTest` resource's compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    destinationEndpoint: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestDestinationEndpoint>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The IP protocol to use in the `PathAnalyzerTest` resource.
     */
    protocol: pulumi.Input<number>;
    /**
     * (Updatable) Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
     */
    protocolParameters?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestProtocolParameters>;
    /**
     * (Updatable) Defines the query options required for a `PathAnalyzerTest` resource.
     */
    queryOptions?: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestQueryOptions>;
    /**
     * (Updatable) Information describing a source or destination in a `PathAnalyzerTest` resource.
     */
    sourceEndpoint: pulumi.Input<inputs.VnMonitoring.PathAnalyzerTestSourceEndpoint>;
}
