// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the External Db System Connector resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Creates a new external connector.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbSystemConnector = new oci.databasemanagement.ExternalDbSystemConnector("test_external_db_system_connector", {
 *     connectorType: externalDbSystemConnectorConnectorType,
 *     externalDbSystemId: testExternalDbSystem.id,
 *     displayName: externalDbSystemConnectorDisplayName,
 * });
 * ```
 *
 * ## Import
 *
 * ExternalDbSystemConnectors can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector test_external_db_system_connector "id"
 * ```
 */
export class ExternalDbSystemConnector extends pulumi.CustomResource {
    /**
     * Get an existing ExternalDbSystemConnector resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExternalDbSystemConnectorState, opts?: pulumi.CustomResourceOptions): ExternalDbSystemConnector {
        return new ExternalDbSystemConnector(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/externalDbSystemConnector:ExternalDbSystemConnector';

    /**
     * Returns true if the given object is an instance of ExternalDbSystemConnector.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExternalDbSystemConnector {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExternalDbSystemConnector.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     */
    public readonly agentId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The error message indicating the reason for connection failure or `null` if the connection was successful.
     */
    public /*out*/ readonly connectionFailureMessage!: pulumi.Output<string>;
    /**
     * The connection details required to connect to an external DB system component.
     */
    public readonly connectionInfos!: pulumi.Output<outputs.DatabaseManagement.ExternalDbSystemConnectorConnectionInfo[]>;
    /**
     * The status of connectivity to the external DB system component.
     */
    public /*out*/ readonly connectionStatus!: pulumi.Output<string>;
    /**
     * (Updatable) The type of connector.
     */
    public readonly connectorType!: pulumi.Output<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The user-friendly name for the external connector. The name does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly externalDbSystemId!: pulumi.Output<string>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the external DB system connector.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the connectionStatus of the external DB system connector was last updated.
     */
    public /*out*/ readonly timeConnectionStatusLastUpdated!: pulumi.Output<string>;
    /**
     * The date and time the external DB system connector was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the external DB system connector was last updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ExternalDbSystemConnector resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExternalDbSystemConnectorArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExternalDbSystemConnectorArgs | ExternalDbSystemConnectorState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExternalDbSystemConnectorState | undefined;
            resourceInputs["agentId"] = state ? state.agentId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionFailureMessage"] = state ? state.connectionFailureMessage : undefined;
            resourceInputs["connectionInfos"] = state ? state.connectionInfos : undefined;
            resourceInputs["connectionStatus"] = state ? state.connectionStatus : undefined;
            resourceInputs["connectorType"] = state ? state.connectorType : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["externalDbSystemId"] = state ? state.externalDbSystemId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeConnectionStatusLastUpdated"] = state ? state.timeConnectionStatusLastUpdated : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ExternalDbSystemConnectorArgs | undefined;
            if ((!args || args.connectorType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'connectorType'");
            }
            if ((!args || args.externalDbSystemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'externalDbSystemId'");
            }
            resourceInputs["agentId"] = args ? args.agentId : undefined;
            resourceInputs["connectionInfos"] = args ? args.connectionInfos : undefined;
            resourceInputs["connectorType"] = args ? args.connectorType : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["externalDbSystemId"] = args ? args.externalDbSystemId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["connectionFailureMessage"] = undefined /*out*/;
            resourceInputs["connectionStatus"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeConnectionStatusLastUpdated"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ExternalDbSystemConnector.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExternalDbSystemConnector resources.
 */
export interface ExternalDbSystemConnectorState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     */
    agentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The error message indicating the reason for connection failure or `null` if the connection was successful.
     */
    connectionFailureMessage?: pulumi.Input<string>;
    /**
     * The connection details required to connect to an external DB system component.
     */
    connectionInfos?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ExternalDbSystemConnectorConnectionInfo>[]>;
    /**
     * The status of connectivity to the external DB system component.
     */
    connectionStatus?: pulumi.Input<string>;
    /**
     * (Updatable) The type of connector.
     */
    connectorType?: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The user-friendly name for the external connector. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    externalDbSystemId?: pulumi.Input<string>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the external DB system connector.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the connectionStatus of the external DB system connector was last updated.
     */
    timeConnectionStatusLastUpdated?: pulumi.Input<string>;
    /**
     * The date and time the external DB system connector was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the external DB system connector was last updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ExternalDbSystemConnector resource.
 */
export interface ExternalDbSystemConnectorArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     */
    agentId?: pulumi.Input<string>;
    /**
     * The connection details required to connect to an external DB system component.
     */
    connectionInfos?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ExternalDbSystemConnectorConnectionInfo>[]>;
    /**
     * (Updatable) The type of connector.
     */
    connectorType: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The user-friendly name for the external connector. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    externalDbSystemId: pulumi.Input<string>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}
