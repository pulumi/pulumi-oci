// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the External My Sql Database Connector resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Creates an external MySQL connector resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalMySqlDatabaseConnector = new oci.databasemanagement.ExternalMySqlDatabaseConnector("test_external_my_sql_database_connector", {
 *     compartmentId: compartmentId,
 *     connectorDetails: {
 *         credentialType: externalMySqlDatabaseConnectorConnectorDetailsCredentialType,
 *         displayName: externalMySqlDatabaseConnectorConnectorDetailsDisplayName,
 *         externalDatabaseId: testExternalDatabase.id,
 *         hostName: externalMySqlDatabaseConnectorConnectorDetailsHostName,
 *         macsAgentId: testAgent.id,
 *         networkProtocol: externalMySqlDatabaseConnectorConnectorDetailsNetworkProtocol,
 *         port: externalMySqlDatabaseConnectorConnectorDetailsPort,
 *         sslSecretId: testSecret.id,
 *     },
 *     isTestConnectionParam: externalMySqlDatabaseConnectorIsTestConnectionParam,
 * });
 * ```
 *
 * ## Import
 *
 * ExternalMySqlDatabaseConnectors can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DatabaseManagement/externalMySqlDatabaseConnector:ExternalMySqlDatabaseConnector test_external_my_sql_database_connector "id"
 * ```
 */
export class ExternalMySqlDatabaseConnector extends pulumi.CustomResource {
    /**
     * Get an existing ExternalMySqlDatabaseConnector resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExternalMySqlDatabaseConnectorState, opts?: pulumi.CustomResourceOptions): ExternalMySqlDatabaseConnector {
        return new ExternalMySqlDatabaseConnector(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/externalMySqlDatabaseConnector:ExternalMySqlDatabaseConnector';

    /**
     * Returns true if the given object is an instance of ExternalMySqlDatabaseConnector.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExternalMySqlDatabaseConnector {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExternalMySqlDatabaseConnector.__pulumiType;
    }

    /**
     * Oracle Cloud Infrastructure Services associated with this connector.
     */
    public /*out*/ readonly associatedServices!: pulumi.Output<string>;
    /**
     * (Updatable) An optional property when incremented triggers Check Connection Status. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly checkConnectionStatusTrigger!: pulumi.Output<number | undefined>;
    /**
     * (Updatable) OCID of compartment for the External MySQL Database.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Connection Status
     */
    public /*out*/ readonly connectionStatus!: pulumi.Output<string>;
    /**
     * (Updatable) Create Details of external database connector.
     */
    public readonly connectorDetails!: pulumi.Output<outputs.DatabaseManagement.ExternalMySqlDatabaseConnectorConnectorDetails>;
    /**
     * Connector Type.
     */
    public /*out*/ readonly connectorType!: pulumi.Output<string>;
    /**
     * Credential type used to connect to database.
     */
    public /*out*/ readonly credentialType!: pulumi.Output<string>;
    /**
     * OCID of MySQL Database resource
     */
    public /*out*/ readonly externalDatabaseId!: pulumi.Output<string>;
    /**
     * Host name for Connector.
     */
    public /*out*/ readonly hostName!: pulumi.Output<string>;
    /**
     * Parameter indicating whether database connection needs to be tested.
     */
    public readonly isTestConnectionParam!: pulumi.Output<boolean>;
    /**
     * Agent Id of the MACS agent.
     */
    public /*out*/ readonly macsAgentId!: pulumi.Output<string>;
    /**
     * External MySQL Database Connector Name.
     */
    public /*out*/ readonly name!: pulumi.Output<string>;
    /**
     * Network Protocol.
     */
    public /*out*/ readonly networkProtocol!: pulumi.Output<string>;
    /**
     * Connector port.
     */
    public /*out*/ readonly port!: pulumi.Output<number>;
    /**
     * Name of MySQL Database.
     */
    public /*out*/ readonly sourceDatabase!: pulumi.Output<string>;
    /**
     * Type of MySQL Database.
     */
    public /*out*/ readonly sourceDatabaseType!: pulumi.Output<string>;
    /**
     * OCID of the SSL secret, if TCPS with SSL is used to connect to database.
     */
    public /*out*/ readonly sslSecretId!: pulumi.Output<string>;
    /**
     * Name of the SSL secret, if TCPS with SSL is used to connect to database.
     */
    public /*out*/ readonly sslSecretName!: pulumi.Output<string>;
    /**
     * Indicates lifecycle  state of the resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Time when connection status was last updated.
     */
    public /*out*/ readonly timeConnectionStatusUpdated!: pulumi.Output<string>;
    /**
     * Connector creation time.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Connector update time.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ExternalMySqlDatabaseConnector resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExternalMySqlDatabaseConnectorArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExternalMySqlDatabaseConnectorArgs | ExternalMySqlDatabaseConnectorState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExternalMySqlDatabaseConnectorState | undefined;
            resourceInputs["associatedServices"] = state ? state.associatedServices : undefined;
            resourceInputs["checkConnectionStatusTrigger"] = state ? state.checkConnectionStatusTrigger : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionStatus"] = state ? state.connectionStatus : undefined;
            resourceInputs["connectorDetails"] = state ? state.connectorDetails : undefined;
            resourceInputs["connectorType"] = state ? state.connectorType : undefined;
            resourceInputs["credentialType"] = state ? state.credentialType : undefined;
            resourceInputs["externalDatabaseId"] = state ? state.externalDatabaseId : undefined;
            resourceInputs["hostName"] = state ? state.hostName : undefined;
            resourceInputs["isTestConnectionParam"] = state ? state.isTestConnectionParam : undefined;
            resourceInputs["macsAgentId"] = state ? state.macsAgentId : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["networkProtocol"] = state ? state.networkProtocol : undefined;
            resourceInputs["port"] = state ? state.port : undefined;
            resourceInputs["sourceDatabase"] = state ? state.sourceDatabase : undefined;
            resourceInputs["sourceDatabaseType"] = state ? state.sourceDatabaseType : undefined;
            resourceInputs["sslSecretId"] = state ? state.sslSecretId : undefined;
            resourceInputs["sslSecretName"] = state ? state.sslSecretName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeConnectionStatusUpdated"] = state ? state.timeConnectionStatusUpdated : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ExternalMySqlDatabaseConnectorArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.connectorDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'connectorDetails'");
            }
            if ((!args || args.isTestConnectionParam === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isTestConnectionParam'");
            }
            resourceInputs["checkConnectionStatusTrigger"] = args ? args.checkConnectionStatusTrigger : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["connectorDetails"] = args ? args.connectorDetails : undefined;
            resourceInputs["isTestConnectionParam"] = args ? args.isTestConnectionParam : undefined;
            resourceInputs["associatedServices"] = undefined /*out*/;
            resourceInputs["connectionStatus"] = undefined /*out*/;
            resourceInputs["connectorType"] = undefined /*out*/;
            resourceInputs["credentialType"] = undefined /*out*/;
            resourceInputs["externalDatabaseId"] = undefined /*out*/;
            resourceInputs["hostName"] = undefined /*out*/;
            resourceInputs["macsAgentId"] = undefined /*out*/;
            resourceInputs["name"] = undefined /*out*/;
            resourceInputs["networkProtocol"] = undefined /*out*/;
            resourceInputs["port"] = undefined /*out*/;
            resourceInputs["sourceDatabase"] = undefined /*out*/;
            resourceInputs["sourceDatabaseType"] = undefined /*out*/;
            resourceInputs["sslSecretId"] = undefined /*out*/;
            resourceInputs["sslSecretName"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeConnectionStatusUpdated"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ExternalMySqlDatabaseConnector.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExternalMySqlDatabaseConnector resources.
 */
export interface ExternalMySqlDatabaseConnectorState {
    /**
     * Oracle Cloud Infrastructure Services associated with this connector.
     */
    associatedServices?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when incremented triggers Check Connection Status. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    checkConnectionStatusTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) OCID of compartment for the External MySQL Database.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Connection Status
     */
    connectionStatus?: pulumi.Input<string>;
    /**
     * (Updatable) Create Details of external database connector.
     */
    connectorDetails?: pulumi.Input<inputs.DatabaseManagement.ExternalMySqlDatabaseConnectorConnectorDetails>;
    /**
     * Connector Type.
     */
    connectorType?: pulumi.Input<string>;
    /**
     * Credential type used to connect to database.
     */
    credentialType?: pulumi.Input<string>;
    /**
     * OCID of MySQL Database resource
     */
    externalDatabaseId?: pulumi.Input<string>;
    /**
     * Host name for Connector.
     */
    hostName?: pulumi.Input<string>;
    /**
     * Parameter indicating whether database connection needs to be tested.
     */
    isTestConnectionParam?: pulumi.Input<boolean>;
    /**
     * Agent Id of the MACS agent.
     */
    macsAgentId?: pulumi.Input<string>;
    /**
     * External MySQL Database Connector Name.
     */
    name?: pulumi.Input<string>;
    /**
     * Network Protocol.
     */
    networkProtocol?: pulumi.Input<string>;
    /**
     * Connector port.
     */
    port?: pulumi.Input<number>;
    /**
     * Name of MySQL Database.
     */
    sourceDatabase?: pulumi.Input<string>;
    /**
     * Type of MySQL Database.
     */
    sourceDatabaseType?: pulumi.Input<string>;
    /**
     * OCID of the SSL secret, if TCPS with SSL is used to connect to database.
     */
    sslSecretId?: pulumi.Input<string>;
    /**
     * Name of the SSL secret, if TCPS with SSL is used to connect to database.
     */
    sslSecretName?: pulumi.Input<string>;
    /**
     * Indicates lifecycle  state of the resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Time when connection status was last updated.
     */
    timeConnectionStatusUpdated?: pulumi.Input<string>;
    /**
     * Connector creation time.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Connector update time.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ExternalMySqlDatabaseConnector resource.
 */
export interface ExternalMySqlDatabaseConnectorArgs {
    /**
     * (Updatable) An optional property when incremented triggers Check Connection Status. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    checkConnectionStatusTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) OCID of compartment for the External MySQL Database.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Create Details of external database connector.
     */
    connectorDetails: pulumi.Input<inputs.DatabaseManagement.ExternalMySqlDatabaseConnectorConnectorDetails>;
    /**
     * Parameter indicating whether database connection needs to be tested.
     */
    isTestConnectionParam: pulumi.Input<boolean>;
}
