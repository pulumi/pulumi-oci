// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Opa Instance resource in Oracle Cloud Infrastructure Opa service.
 *
 * Creates a new OpaInstance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOpaInstance = new oci.opa.OpaInstance("test_opa_instance", {
 *     compartmentId: compartmentId,
 *     displayName: opaInstanceDisplayName,
 *     shapeName: testShape.name,
 *     consumptionModel: opaInstanceConsumptionModel,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: opaInstanceDescription,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     idcsAt: opaInstanceIdcsAt,
 *     isBreakglassEnabled: opaInstanceIsBreakglassEnabled,
 *     meteringType: opaInstanceMeteringType,
 * });
 * ```
 *
 * ## Import
 *
 * OpaInstances can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Opa/opaInstance:OpaInstance test_opa_instance "id"
 * ```
 */
export class OpaInstance extends pulumi.CustomResource {
    /**
     * Get an existing OpaInstance resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OpaInstanceState, opts?: pulumi.CustomResourceOptions): OpaInstance {
        return new OpaInstance(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Opa/opaInstance:OpaInstance';

    /**
     * Returns true if the given object is an instance of OpaInstance.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OpaInstance {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OpaInstance.__pulumiType;
    }

    /**
     * A list of associated attachments to other services
     */
    public /*out*/ readonly attachments!: pulumi.Output<outputs.Opa.OpaInstanceAttachment[]>;
    /**
     * (Updatable) Compartment Identifier
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Parameter specifying which entitlement to use for billing purposes
     */
    public readonly consumptionModel!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Description of the Oracle Process Automation instance.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
     */
    public readonly idcsAt!: pulumi.Output<string>;
    /**
     * This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    public /*out*/ readonly identityAppDisplayName!: pulumi.Output<string>;
    /**
     * This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
     */
    public /*out*/ readonly identityAppGuid!: pulumi.Output<string>;
    /**
     * This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    public /*out*/ readonly identityAppOpcServiceInstanceGuid!: pulumi.Output<string>;
    /**
     * This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    public /*out*/ readonly identityDomainUrl!: pulumi.Output<string>;
    /**
     * OPA Instance URL
     */
    public /*out*/ readonly instanceUrl!: pulumi.Output<string>;
    /**
     * indicates if breakGlass is enabled for the opa instance.
     */
    public readonly isBreakglassEnabled!: pulumi.Output<boolean>;
    /**
     * MeteringType Identifier
     */
    public readonly meteringType!: pulumi.Output<string>;
    /**
     * Shape of the instance.
     */
    public readonly shapeName!: pulumi.Output<string>;
    /**
     * (Updatable) The target state for the Opa Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time when OpaInstance was created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the OpaInstance was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a OpaInstance resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OpaInstanceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OpaInstanceArgs | OpaInstanceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OpaInstanceState | undefined;
            resourceInputs["attachments"] = state ? state.attachments : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["consumptionModel"] = state ? state.consumptionModel : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["idcsAt"] = state ? state.idcsAt : undefined;
            resourceInputs["identityAppDisplayName"] = state ? state.identityAppDisplayName : undefined;
            resourceInputs["identityAppGuid"] = state ? state.identityAppGuid : undefined;
            resourceInputs["identityAppOpcServiceInstanceGuid"] = state ? state.identityAppOpcServiceInstanceGuid : undefined;
            resourceInputs["identityDomainUrl"] = state ? state.identityDomainUrl : undefined;
            resourceInputs["instanceUrl"] = state ? state.instanceUrl : undefined;
            resourceInputs["isBreakglassEnabled"] = state ? state.isBreakglassEnabled : undefined;
            resourceInputs["meteringType"] = state ? state.meteringType : undefined;
            resourceInputs["shapeName"] = state ? state.shapeName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as OpaInstanceArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["consumptionModel"] = args ? args.consumptionModel : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["idcsAt"] = args ? args.idcsAt : undefined;
            resourceInputs["isBreakglassEnabled"] = args ? args.isBreakglassEnabled : undefined;
            resourceInputs["meteringType"] = args ? args.meteringType : undefined;
            resourceInputs["shapeName"] = args ? args.shapeName : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["attachments"] = undefined /*out*/;
            resourceInputs["identityAppDisplayName"] = undefined /*out*/;
            resourceInputs["identityAppGuid"] = undefined /*out*/;
            resourceInputs["identityAppOpcServiceInstanceGuid"] = undefined /*out*/;
            resourceInputs["identityDomainUrl"] = undefined /*out*/;
            resourceInputs["instanceUrl"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(OpaInstance.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OpaInstance resources.
 */
export interface OpaInstanceState {
    /**
     * A list of associated attachments to other services
     */
    attachments?: pulumi.Input<pulumi.Input<inputs.Opa.OpaInstanceAttachment>[]>;
    /**
     * (Updatable) Compartment Identifier
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Parameter specifying which entitlement to use for billing purposes
     */
    consumptionModel?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Description of the Oracle Process Automation instance.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
     */
    idcsAt?: pulumi.Input<string>;
    /**
     * This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    identityAppDisplayName?: pulumi.Input<string>;
    /**
     * This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
     */
    identityAppGuid?: pulumi.Input<string>;
    /**
     * This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    identityAppOpcServiceInstanceGuid?: pulumi.Input<string>;
    /**
     * This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    identityDomainUrl?: pulumi.Input<string>;
    /**
     * OPA Instance URL
     */
    instanceUrl?: pulumi.Input<string>;
    /**
     * indicates if breakGlass is enabled for the opa instance.
     */
    isBreakglassEnabled?: pulumi.Input<boolean>;
    /**
     * MeteringType Identifier
     */
    meteringType?: pulumi.Input<string>;
    /**
     * Shape of the instance.
     */
    shapeName?: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Opa Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time when OpaInstance was created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the OpaInstance was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OpaInstance resource.
 */
export interface OpaInstanceArgs {
    /**
     * (Updatable) Compartment Identifier
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Parameter specifying which entitlement to use for billing purposes
     */
    consumptionModel?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Description of the Oracle Process Automation instance.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
     */
    idcsAt?: pulumi.Input<string>;
    /**
     * indicates if breakGlass is enabled for the opa instance.
     */
    isBreakglassEnabled?: pulumi.Input<boolean>;
    /**
     * MeteringType Identifier
     */
    meteringType?: pulumi.Input<string>;
    /**
     * Shape of the instance.
     */
    shapeName: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Opa Instance. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
}
