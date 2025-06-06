// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Analytics Instance resource in Oracle Cloud Infrastructure Analytics service.
 *
 * Create a new AnalyticsInstance in the specified compartment. The operation is long-running
 * and creates a new WorkRequest.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAnalyticsInstance = new oci.analytics.AnalyticsInstance("test_analytics_instance", {
 *     capacity: {
 *         capacityType: analyticsInstanceCapacityCapacityType,
 *         capacityValue: analyticsInstanceCapacityCapacityValue,
 *     },
 *     compartmentId: compartmentId,
 *     featureSet: analyticsInstanceFeatureSet,
 *     idcsAccessToken: analyticsInstanceIdcsAccessToken,
 *     licenseType: analyticsInstanceLicenseType,
 *     name: analyticsInstanceName,
 *     adminUser: analyticsInstanceAdminUser,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: analyticsInstanceDescription,
 *     domainId: testDomain.id,
 *     emailNotification: analyticsInstanceEmailNotification,
 *     featureBundle: analyticsInstanceFeatureBundle,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     kmsKeyId: testKey.id,
 *     networkEndpointDetails: {
 *         networkEndpointType: analyticsInstanceNetworkEndpointDetailsNetworkEndpointType,
 *         networkSecurityGroupIds: analyticsInstanceNetworkEndpointDetailsNetworkSecurityGroupIds,
 *         subnetId: testSubnet.id,
 *         vcnId: testVcn.id,
 *         whitelistedIps: analyticsInstanceNetworkEndpointDetailsWhitelistedIps,
 *         whitelistedServices: analyticsInstanceNetworkEndpointDetailsWhitelistedServices,
 *         whitelistedVcns: [{
 *             id: analyticsInstanceNetworkEndpointDetailsWhitelistedVcnsId,
 *             whitelistedIps: analyticsInstanceNetworkEndpointDetailsWhitelistedVcnsWhitelistedIps,
 *         }],
 *     },
 *     updateChannel: analyticsInstanceUpdateChannel,
 * });
 * ```
 *
 * ## Import
 *
 * AnalyticsInstances can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Analytics/analyticsInstance:AnalyticsInstance test_analytics_instance "id"
 * ```
 */
export class AnalyticsInstance extends pulumi.CustomResource {
    /**
     * Get an existing AnalyticsInstance resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AnalyticsInstanceState, opts?: pulumi.CustomResourceOptions): AnalyticsInstance {
        return new AnalyticsInstance(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Analytics/analyticsInstance:AnalyticsInstance';

    /**
     * Returns true if the given object is an instance of AnalyticsInstance.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AnalyticsInstance {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AnalyticsInstance.__pulumiType;
    }

    /**
     * user name of the authorized user.
     */
    public readonly adminUser!: pulumi.Output<string>;
    /**
     * Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
     */
    public readonly capacity!: pulumi.Output<outputs.Analytics.AnalyticsInstanceCapacity>;
    /**
     * (Updatable) The OCID of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Optional description.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * domain id for which the user is authorized.
     */
    public readonly domainId!: pulumi.Output<string>;
    /**
     * (Updatable) Email address receiving notifications.
     */
    public readonly emailNotification!: pulumi.Output<string>;
    /**
     * The feature set of an Analytics instance.
     */
    public readonly featureBundle!: pulumi.Output<string>;
    /**
     * Analytics feature set.
     */
    public readonly featureSet!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * IDCS access token identifying a stripe and service administrator user.
     */
    public readonly idcsAccessToken!: pulumi.Output<string | undefined>;
    /**
     * OCID of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
     */
    public readonly kmsKeyId!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) The license used for the service.
     */
    public readonly licenseType!: pulumi.Output<string>;
    /**
     * The name of the Analytics instance. This name must be unique in the tenancy and cannot be changed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Base representation of a network endpoint.
     */
    public readonly networkEndpointDetails!: pulumi.Output<outputs.Analytics.AnalyticsInstanceNetworkEndpointDetails>;
    /**
     * URL of the Analytics service.
     */
    public /*out*/ readonly serviceUrl!: pulumi.Output<string>;
    /**
     * (Updatable) The target state for the Analytics Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.key": "value"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) Analytics instance update channel.
     */
    public readonly updateChannel!: pulumi.Output<string>;

    /**
     * Create a AnalyticsInstance resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AnalyticsInstanceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AnalyticsInstanceArgs | AnalyticsInstanceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AnalyticsInstanceState | undefined;
            resourceInputs["adminUser"] = state ? state.adminUser : undefined;
            resourceInputs["capacity"] = state ? state.capacity : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["domainId"] = state ? state.domainId : undefined;
            resourceInputs["emailNotification"] = state ? state.emailNotification : undefined;
            resourceInputs["featureBundle"] = state ? state.featureBundle : undefined;
            resourceInputs["featureSet"] = state ? state.featureSet : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["idcsAccessToken"] = state ? state.idcsAccessToken : undefined;
            resourceInputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            resourceInputs["licenseType"] = state ? state.licenseType : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkEndpointDetails"] = state ? state.networkEndpointDetails : undefined;
            resourceInputs["serviceUrl"] = state ? state.serviceUrl : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["updateChannel"] = state ? state.updateChannel : undefined;
        } else {
            const args = argsOrState as AnalyticsInstanceArgs | undefined;
            if ((!args || args.capacity === undefined) && !opts.urn) {
                throw new Error("Missing required property 'capacity'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.featureSet === undefined) && !opts.urn) {
                throw new Error("Missing required property 'featureSet'");
            }
            if ((!args || args.licenseType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'licenseType'");
            }
            resourceInputs["adminUser"] = args ? args.adminUser : undefined;
            resourceInputs["capacity"] = args ? args.capacity : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["domainId"] = args ? args.domainId : undefined;
            resourceInputs["emailNotification"] = args ? args.emailNotification : undefined;
            resourceInputs["featureBundle"] = args ? args.featureBundle : undefined;
            resourceInputs["featureSet"] = args ? args.featureSet : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["idcsAccessToken"] = args?.idcsAccessToken ? pulumi.secret(args.idcsAccessToken) : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["licenseType"] = args ? args.licenseType : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["networkEndpointDetails"] = args ? args.networkEndpointDetails : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["updateChannel"] = args ? args.updateChannel : undefined;
            resourceInputs["serviceUrl"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const secretOpts = { additionalSecretOutputs: ["idcsAccessToken"] };
        opts = pulumi.mergeOptions(opts, secretOpts);
        super(AnalyticsInstance.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AnalyticsInstance resources.
 */
export interface AnalyticsInstanceState {
    /**
     * user name of the authorized user.
     */
    adminUser?: pulumi.Input<string>;
    /**
     * Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
     */
    capacity?: pulumi.Input<inputs.Analytics.AnalyticsInstanceCapacity>;
    /**
     * (Updatable) The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Optional description.
     */
    description?: pulumi.Input<string>;
    /**
     * domain id for which the user is authorized.
     */
    domainId?: pulumi.Input<string>;
    /**
     * (Updatable) Email address receiving notifications.
     */
    emailNotification?: pulumi.Input<string>;
    /**
     * The feature set of an Analytics instance.
     */
    featureBundle?: pulumi.Input<string>;
    /**
     * Analytics feature set.
     */
    featureSet?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * IDCS access token identifying a stripe and service administrator user.
     */
    idcsAccessToken?: pulumi.Input<string>;
    /**
     * OCID of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) The license used for the service.
     */
    licenseType?: pulumi.Input<string>;
    /**
     * The name of the Analytics instance. This name must be unique in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * Base representation of a network endpoint.
     */
    networkEndpointDetails?: pulumi.Input<inputs.Analytics.AnalyticsInstanceNetworkEndpointDetails>;
    /**
     * URL of the Analytics service.
     */
    serviceUrl?: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Analytics Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.key": "value"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) Analytics instance update channel.
     */
    updateChannel?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AnalyticsInstance resource.
 */
export interface AnalyticsInstanceArgs {
    /**
     * user name of the authorized user.
     */
    adminUser?: pulumi.Input<string>;
    /**
     * Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
     */
    capacity: pulumi.Input<inputs.Analytics.AnalyticsInstanceCapacity>;
    /**
     * (Updatable) The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Optional description.
     */
    description?: pulumi.Input<string>;
    /**
     * domain id for which the user is authorized.
     */
    domainId?: pulumi.Input<string>;
    /**
     * (Updatable) Email address receiving notifications.
     */
    emailNotification?: pulumi.Input<string>;
    /**
     * The feature set of an Analytics instance.
     */
    featureBundle?: pulumi.Input<string>;
    /**
     * Analytics feature set.
     */
    featureSet: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * IDCS access token identifying a stripe and service administrator user.
     */
    idcsAccessToken?: pulumi.Input<string>;
    /**
     * OCID of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) The license used for the service.
     */
    licenseType: pulumi.Input<string>;
    /**
     * The name of the Analytics instance. This name must be unique in the tenancy and cannot be changed.
     */
    name?: pulumi.Input<string>;
    /**
     * Base representation of a network endpoint.
     */
    networkEndpointDetails?: pulumi.Input<inputs.Analytics.AnalyticsInstanceNetworkEndpointDetails>;
    /**
     * (Updatable) The target state for the Analytics Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Analytics instance update channel.
     */
    updateChannel?: pulumi.Input<string>;
}
