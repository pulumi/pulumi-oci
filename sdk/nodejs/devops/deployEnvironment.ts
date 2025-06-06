// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Deploy Environment resource in Oracle Cloud Infrastructure Devops service.
 *
 * Creates a new deployment environment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployEnvironment = new oci.devops.DeployEnvironment("test_deploy_environment", {
 *     deployEnvironmentType: deployEnvironmentDeployEnvironmentType,
 *     projectId: testProject.id,
 *     clusterId: testCluster.id,
 *     computeInstanceGroupSelectors: {
 *         items: [{
 *             selectorType: deployEnvironmentComputeInstanceGroupSelectorsItemsSelectorType,
 *             computeInstanceIds: deployEnvironmentComputeInstanceGroupSelectorsItemsComputeInstanceIds,
 *             query: deployEnvironmentComputeInstanceGroupSelectorsItemsQuery,
 *             region: deployEnvironmentComputeInstanceGroupSelectorsItemsRegion,
 *         }],
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: deployEnvironmentDescription,
 *     displayName: deployEnvironmentDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     functionId: testFunction.id,
 *     networkChannel: {
 *         networkChannelType: deployEnvironmentNetworkChannelNetworkChannelType,
 *         subnetId: testSubnet.id,
 *         nsgIds: deployEnvironmentNetworkChannelNsgIds,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * DeployEnvironments can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DevOps/deployEnvironment:DeployEnvironment test_deploy_environment "id"
 * ```
 */
export class DeployEnvironment extends pulumi.CustomResource {
    /**
     * Get an existing DeployEnvironment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DeployEnvironmentState, opts?: pulumi.CustomResourceOptions): DeployEnvironment {
        return new DeployEnvironment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DevOps/deployEnvironment:DeployEnvironment';

    /**
     * Returns true if the given object is an instance of DeployEnvironment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DeployEnvironment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DeployEnvironment.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the Kubernetes cluster.
     */
    public readonly clusterId!: pulumi.Output<string>;
    /**
     * The OCID of a compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
     */
    public readonly computeInstanceGroupSelectors!: pulumi.Output<outputs.DevOps.DeployEnvironmentComputeInstanceGroupSelectors>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Deployment environment type.
     */
    public readonly deployEnvironmentType!: pulumi.Output<string>;
    /**
     * (Updatable) Optional description about the deployment environment.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Deployment environment display name. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The OCID of the Function.
     */
    public readonly functionId!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
     */
    public readonly networkChannel!: pulumi.Output<outputs.DevOps.DeployEnvironmentNetworkChannel>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * The current state of the deployment environment.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DeployEnvironment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DeployEnvironmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DeployEnvironmentArgs | DeployEnvironmentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DeployEnvironmentState | undefined;
            resourceInputs["clusterId"] = state ? state.clusterId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["computeInstanceGroupSelectors"] = state ? state.computeInstanceGroupSelectors : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deployEnvironmentType"] = state ? state.deployEnvironmentType : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["functionId"] = state ? state.functionId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["networkChannel"] = state ? state.networkChannel : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DeployEnvironmentArgs | undefined;
            if ((!args || args.deployEnvironmentType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'deployEnvironmentType'");
            }
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            resourceInputs["clusterId"] = args ? args.clusterId : undefined;
            resourceInputs["computeInstanceGroupSelectors"] = args ? args.computeInstanceGroupSelectors : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["deployEnvironmentType"] = args ? args.deployEnvironmentType : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["functionId"] = args ? args.functionId : undefined;
            resourceInputs["networkChannel"] = args ? args.networkChannel : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DeployEnvironment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DeployEnvironment resources.
 */
export interface DeployEnvironmentState {
    /**
     * (Updatable) The OCID of the Kubernetes cluster.
     */
    clusterId?: pulumi.Input<string>;
    /**
     * The OCID of a compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
     */
    computeInstanceGroupSelectors?: pulumi.Input<inputs.DevOps.DeployEnvironmentComputeInstanceGroupSelectors>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Deployment environment type.
     */
    deployEnvironmentType?: pulumi.Input<string>;
    /**
     * (Updatable) Optional description about the deployment environment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment environment display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the Function.
     */
    functionId?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
     */
    networkChannel?: pulumi.Input<inputs.DevOps.DeployEnvironmentNetworkChannel>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId?: pulumi.Input<string>;
    /**
     * The current state of the deployment environment.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DeployEnvironment resource.
 */
export interface DeployEnvironmentArgs {
    /**
     * (Updatable) The OCID of the Kubernetes cluster.
     */
    clusterId?: pulumi.Input<string>;
    /**
     * (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
     */
    computeInstanceGroupSelectors?: pulumi.Input<inputs.DevOps.DeployEnvironmentComputeInstanceGroupSelectors>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Deployment environment type.
     */
    deployEnvironmentType: pulumi.Input<string>;
    /**
     * (Updatable) Optional description about the deployment environment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment environment display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the Function.
     */
    functionId?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
     */
    networkChannel?: pulumi.Input<inputs.DevOps.DeployEnvironmentNetworkChannel>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId: pulumi.Input<string>;
}
