// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * ## Example Usage
 *
 * ## Import
 *
 * DatabaseInsights can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Opsi/databaseInsight:DatabaseInsight test_database_insight "id"
 * ```
 */
export class DatabaseInsight extends pulumi.CustomResource {
    /**
     * Get an existing DatabaseInsight resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DatabaseInsightState, opts?: pulumi.CustomResourceOptions): DatabaseInsight {
        return new DatabaseInsight(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Opsi/databaseInsight:DatabaseInsight';

    /**
     * Returns true if the given object is an instance of DatabaseInsight.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DatabaseInsight {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DatabaseInsight.__pulumiType;
    }

    /**
     * (Updatable) Compartment Identifier of database
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * User credential details to connect to the database.
     */
    public readonly connectionCredentialDetails!: pulumi.Output<outputs.Opsi.DatabaseInsightConnectionCredentialDetails>;
    /**
     * Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    public readonly connectionDetails!: pulumi.Output<outputs.Opsi.DatabaseInsightConnectionDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of External Database Connector
     */
    public readonly connectorId!: pulumi.Output<string>;
    /**
     * User credential details to connect to the database.
     */
    public readonly credentialDetails!: pulumi.Output<outputs.Opsi.DatabaseInsightCredentialDetails | undefined>;
    /**
     * A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     */
    public readonly databaseConnectionStatusDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The DBM owned database connector [OCID](https://www.terraform.io/iaas/database-management/doc/view-connector-details.html) mapping to the database credentials and connection details.
     */
    public readonly databaseConnectorId!: pulumi.Output<string>;
    /**
     * Display name of database
     */
    public /*out*/ readonly databaseDisplayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     */
    public readonly databaseId!: pulumi.Output<string>;
    /**
     * Name of database
     */
    public /*out*/ readonly databaseName!: pulumi.Output<string>;
    /**
     * Oracle Cloud Infrastructure database resource type
     */
    public readonly databaseResourceType!: pulumi.Output<string>;
    /**
     * Ops Insights internal representation of the database type.
     */
    public /*out*/ readonly databaseType!: pulumi.Output<string>;
    /**
     * The version of the database.
     */
    public /*out*/ readonly databaseVersion!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint. This field and opsiPrivateEndpointId are mutually exclusive. If DBM private endpoint ID is provided, a new OPSI private endpoint ID will be created.
     */
    public readonly dbmPrivateEndpointId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Database Deployment Type (EXACS will be supported in the future)
     */
    public readonly deploymentType!: pulumi.Output<string>;
    /**
     * OPSI Enterprise Manager Bridge OCID
     */
    public readonly enterpriseManagerBridgeId!: pulumi.Output<string>;
    /**
     * Enterprise Manager Entity Display Name
     */
    public /*out*/ readonly enterpriseManagerEntityDisplayName!: pulumi.Output<string>;
    /**
     * Enterprise Manager Entity Unique Identifier
     */
    public readonly enterpriseManagerEntityIdentifier!: pulumi.Output<string>;
    /**
     * Enterprise Manager Entity Name
     */
    public /*out*/ readonly enterpriseManagerEntityName!: pulumi.Output<string>;
    /**
     * Enterprise Manager Entity Type
     */
    public /*out*/ readonly enterpriseManagerEntityType!: pulumi.Output<string>;
    /**
     * Enterprise Manager Unique Identifier
     */
    public readonly enterpriseManagerIdentifier!: pulumi.Output<string>;
    /**
     * (Updatable) Source of the database entity.
     */
    public readonly entitySource!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     */
    public readonly exadataInsightId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Flag is to identify if advanced features for autonomous database is enabled or not
     */
    public readonly isAdvancedFeaturesEnabled!: pulumi.Output<boolean>;
    /**
     * Specifies if MYSQL DB System has heatwave cluster attached.
     */
    public /*out*/ readonly isHeatWaveClusterAttached!: pulumi.Output<boolean>;
    /**
     * Specifies if MYSQL DB System is highly available.
     */
    public /*out*/ readonly isHighlyAvailable!: pulumi.Output<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
     */
    public readonly managementAgentId!: pulumi.Output<string | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     */
    public readonly opsiPrivateEndpointId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster or DB System ID, depending on which configuration the resource belongs to.
     */
    public /*out*/ readonly parentId!: pulumi.Output<string>;
    /**
     * Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
     */
    public /*out*/ readonly processorCount!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Infrastructure.
     */
    public /*out*/ readonly rootId!: pulumi.Output<string>;
    /**
     * Database service name used for connection requests.
     */
    public readonly serviceName!: pulumi.Output<string>;
    /**
     * The current state of the database.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) Status of the resource. Example: "ENABLED", "DISABLED". Resource can be either enabled or disabled by updating the value of status field to either "ENABLED" or "DISABLED"
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values. The resource destruction here is basically a soft delete. User cannot create resource using the same EM managed bridge OCID. If resource is in enabled state during destruction, the resource will be disabled automatically before performing delete operation.
     */
    public readonly status!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time the database insight was first enabled. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the database insight was updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DatabaseInsight resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DatabaseInsightArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DatabaseInsightArgs | DatabaseInsightState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DatabaseInsightState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionCredentialDetails"] = state ? state.connectionCredentialDetails : undefined;
            resourceInputs["connectionDetails"] = state ? state.connectionDetails : undefined;
            resourceInputs["connectorId"] = state ? state.connectorId : undefined;
            resourceInputs["credentialDetails"] = state ? state.credentialDetails : undefined;
            resourceInputs["databaseConnectionStatusDetails"] = state ? state.databaseConnectionStatusDetails : undefined;
            resourceInputs["databaseConnectorId"] = state ? state.databaseConnectorId : undefined;
            resourceInputs["databaseDisplayName"] = state ? state.databaseDisplayName : undefined;
            resourceInputs["databaseId"] = state ? state.databaseId : undefined;
            resourceInputs["databaseName"] = state ? state.databaseName : undefined;
            resourceInputs["databaseResourceType"] = state ? state.databaseResourceType : undefined;
            resourceInputs["databaseType"] = state ? state.databaseType : undefined;
            resourceInputs["databaseVersion"] = state ? state.databaseVersion : undefined;
            resourceInputs["dbmPrivateEndpointId"] = state ? state.dbmPrivateEndpointId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deploymentType"] = state ? state.deploymentType : undefined;
            resourceInputs["enterpriseManagerBridgeId"] = state ? state.enterpriseManagerBridgeId : undefined;
            resourceInputs["enterpriseManagerEntityDisplayName"] = state ? state.enterpriseManagerEntityDisplayName : undefined;
            resourceInputs["enterpriseManagerEntityIdentifier"] = state ? state.enterpriseManagerEntityIdentifier : undefined;
            resourceInputs["enterpriseManagerEntityName"] = state ? state.enterpriseManagerEntityName : undefined;
            resourceInputs["enterpriseManagerEntityType"] = state ? state.enterpriseManagerEntityType : undefined;
            resourceInputs["enterpriseManagerIdentifier"] = state ? state.enterpriseManagerIdentifier : undefined;
            resourceInputs["entitySource"] = state ? state.entitySource : undefined;
            resourceInputs["exadataInsightId"] = state ? state.exadataInsightId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isAdvancedFeaturesEnabled"] = state ? state.isAdvancedFeaturesEnabled : undefined;
            resourceInputs["isHeatWaveClusterAttached"] = state ? state.isHeatWaveClusterAttached : undefined;
            resourceInputs["isHighlyAvailable"] = state ? state.isHighlyAvailable : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["managementAgentId"] = state ? state.managementAgentId : undefined;
            resourceInputs["opsiPrivateEndpointId"] = state ? state.opsiPrivateEndpointId : undefined;
            resourceInputs["parentId"] = state ? state.parentId : undefined;
            resourceInputs["processorCount"] = state ? state.processorCount : undefined;
            resourceInputs["rootId"] = state ? state.rootId : undefined;
            resourceInputs["serviceName"] = state ? state.serviceName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DatabaseInsightArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.entitySource === undefined) && !opts.urn) {
                throw new Error("Missing required property 'entitySource'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["connectionCredentialDetails"] = args ? args.connectionCredentialDetails : undefined;
            resourceInputs["connectionDetails"] = args ? args.connectionDetails : undefined;
            resourceInputs["connectorId"] = args ? args.connectorId : undefined;
            resourceInputs["credentialDetails"] = args ? args.credentialDetails : undefined;
            resourceInputs["databaseConnectionStatusDetails"] = args ? args.databaseConnectionStatusDetails : undefined;
            resourceInputs["databaseConnectorId"] = args ? args.databaseConnectorId : undefined;
            resourceInputs["databaseId"] = args ? args.databaseId : undefined;
            resourceInputs["databaseResourceType"] = args ? args.databaseResourceType : undefined;
            resourceInputs["dbmPrivateEndpointId"] = args ? args.dbmPrivateEndpointId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["deploymentType"] = args ? args.deploymentType : undefined;
            resourceInputs["enterpriseManagerBridgeId"] = args ? args.enterpriseManagerBridgeId : undefined;
            resourceInputs["enterpriseManagerEntityIdentifier"] = args ? args.enterpriseManagerEntityIdentifier : undefined;
            resourceInputs["enterpriseManagerIdentifier"] = args ? args.enterpriseManagerIdentifier : undefined;
            resourceInputs["entitySource"] = args ? args.entitySource : undefined;
            resourceInputs["exadataInsightId"] = args ? args.exadataInsightId : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isAdvancedFeaturesEnabled"] = args ? args.isAdvancedFeaturesEnabled : undefined;
            resourceInputs["managementAgentId"] = args ? args.managementAgentId : undefined;
            resourceInputs["opsiPrivateEndpointId"] = args ? args.opsiPrivateEndpointId : undefined;
            resourceInputs["serviceName"] = args ? args.serviceName : undefined;
            resourceInputs["status"] = args ? args.status : undefined;
            resourceInputs["databaseDisplayName"] = undefined /*out*/;
            resourceInputs["databaseName"] = undefined /*out*/;
            resourceInputs["databaseType"] = undefined /*out*/;
            resourceInputs["databaseVersion"] = undefined /*out*/;
            resourceInputs["enterpriseManagerEntityDisplayName"] = undefined /*out*/;
            resourceInputs["enterpriseManagerEntityName"] = undefined /*out*/;
            resourceInputs["enterpriseManagerEntityType"] = undefined /*out*/;
            resourceInputs["isHeatWaveClusterAttached"] = undefined /*out*/;
            resourceInputs["isHighlyAvailable"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["parentId"] = undefined /*out*/;
            resourceInputs["processorCount"] = undefined /*out*/;
            resourceInputs["rootId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DatabaseInsight.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DatabaseInsight resources.
 */
export interface DatabaseInsightState {
    /**
     * (Updatable) Compartment Identifier of database
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * User credential details to connect to the database.
     */
    connectionCredentialDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightConnectionCredentialDetails>;
    /**
     * Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    connectionDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightConnectionDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of External Database Connector
     */
    connectorId?: pulumi.Input<string>;
    /**
     * User credential details to connect to the database.
     */
    credentialDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightCredentialDetails>;
    /**
     * A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     */
    databaseConnectionStatusDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The DBM owned database connector [OCID](https://www.terraform.io/iaas/database-management/doc/view-connector-details.html) mapping to the database credentials and connection details.
     */
    databaseConnectorId?: pulumi.Input<string>;
    /**
     * Display name of database
     */
    databaseDisplayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     */
    databaseId?: pulumi.Input<string>;
    /**
     * Name of database
     */
    databaseName?: pulumi.Input<string>;
    /**
     * Oracle Cloud Infrastructure database resource type
     */
    databaseResourceType?: pulumi.Input<string>;
    /**
     * Ops Insights internal representation of the database type.
     */
    databaseType?: pulumi.Input<string>;
    /**
     * The version of the database.
     */
    databaseVersion?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint. This field and opsiPrivateEndpointId are mutually exclusive. If DBM private endpoint ID is provided, a new OPSI private endpoint ID will be created.
     */
    dbmPrivateEndpointId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Database Deployment Type (EXACS will be supported in the future)
     */
    deploymentType?: pulumi.Input<string>;
    /**
     * OPSI Enterprise Manager Bridge OCID
     */
    enterpriseManagerBridgeId?: pulumi.Input<string>;
    /**
     * Enterprise Manager Entity Display Name
     */
    enterpriseManagerEntityDisplayName?: pulumi.Input<string>;
    /**
     * Enterprise Manager Entity Unique Identifier
     */
    enterpriseManagerEntityIdentifier?: pulumi.Input<string>;
    /**
     * Enterprise Manager Entity Name
     */
    enterpriseManagerEntityName?: pulumi.Input<string>;
    /**
     * Enterprise Manager Entity Type
     */
    enterpriseManagerEntityType?: pulumi.Input<string>;
    /**
     * Enterprise Manager Unique Identifier
     */
    enterpriseManagerIdentifier?: pulumi.Input<string>;
    /**
     * (Updatable) Source of the database entity.
     */
    entitySource?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     */
    exadataInsightId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Flag is to identify if advanced features for autonomous database is enabled or not
     */
    isAdvancedFeaturesEnabled?: pulumi.Input<boolean>;
    /**
     * Specifies if MYSQL DB System has heatwave cluster attached.
     */
    isHeatWaveClusterAttached?: pulumi.Input<boolean>;
    /**
     * Specifies if MYSQL DB System is highly available.
     */
    isHighlyAvailable?: pulumi.Input<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
     */
    managementAgentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     */
    opsiPrivateEndpointId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster or DB System ID, depending on which configuration the resource belongs to.
     */
    parentId?: pulumi.Input<string>;
    /**
     * Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
     */
    processorCount?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Infrastructure.
     */
    rootId?: pulumi.Input<string>;
    /**
     * Database service name used for connection requests.
     */
    serviceName?: pulumi.Input<string>;
    /**
     * The current state of the database.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Status of the resource. Example: "ENABLED", "DISABLED". Resource can be either enabled or disabled by updating the value of status field to either "ENABLED" or "DISABLED"
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values. The resource destruction here is basically a soft delete. User cannot create resource using the same EM managed bridge OCID. If resource is in enabled state during destruction, the resource will be disabled automatically before performing delete operation.
     */
    status?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time the database insight was first enabled. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the database insight was updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DatabaseInsight resource.
 */
export interface DatabaseInsightArgs {
    /**
     * (Updatable) Compartment Identifier of database
     */
    compartmentId: pulumi.Input<string>;
    /**
     * User credential details to connect to the database.
     */
    connectionCredentialDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightConnectionCredentialDetails>;
    /**
     * Connection details to connect to the database. HostName, protocol, and port should be specified.
     */
    connectionDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightConnectionDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of External Database Connector
     */
    connectorId?: pulumi.Input<string>;
    /**
     * User credential details to connect to the database.
     */
    credentialDetails?: pulumi.Input<inputs.Opsi.DatabaseInsightCredentialDetails>;
    /**
     * A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     */
    databaseConnectionStatusDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The DBM owned database connector [OCID](https://www.terraform.io/iaas/database-management/doc/view-connector-details.html) mapping to the database credentials and connection details.
     */
    databaseConnectorId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     */
    databaseId?: pulumi.Input<string>;
    /**
     * Oracle Cloud Infrastructure database resource type
     */
    databaseResourceType?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint. This field and opsiPrivateEndpointId are mutually exclusive. If DBM private endpoint ID is provided, a new OPSI private endpoint ID will be created.
     */
    dbmPrivateEndpointId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Database Deployment Type (EXACS will be supported in the future)
     */
    deploymentType?: pulumi.Input<string>;
    /**
     * OPSI Enterprise Manager Bridge OCID
     */
    enterpriseManagerBridgeId?: pulumi.Input<string>;
    /**
     * Enterprise Manager Entity Unique Identifier
     */
    enterpriseManagerEntityIdentifier?: pulumi.Input<string>;
    /**
     * Enterprise Manager Unique Identifier
     */
    enterpriseManagerIdentifier?: pulumi.Input<string>;
    /**
     * (Updatable) Source of the database entity.
     */
    entitySource: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     */
    exadataInsightId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Flag is to identify if advanced features for autonomous database is enabled or not
     */
    isAdvancedFeaturesEnabled?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
     */
    managementAgentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     */
    opsiPrivateEndpointId?: pulumi.Input<string>;
    /**
     * Database service name used for connection requests.
     */
    serviceName?: pulumi.Input<string>;
    /**
     * (Updatable) Status of the resource. Example: "ENABLED", "DISABLED". Resource can be either enabled or disabled by updating the value of status field to either "ENABLED" or "DISABLED"
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values. The resource destruction here is basically a soft delete. User cannot create resource using the same EM managed bridge OCID. If resource is in enabled state during destruction, the resource will be disabled automatically before performing delete operation.
     */
    status?: pulumi.Input<string>;
}
