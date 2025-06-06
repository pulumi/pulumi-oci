// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Target Database resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Registers the specified database with Data Safe and creates a Data Safe target database in the Data Safe Console.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabase = new oci.datasafe.TargetDatabase("test_target_database", {
 *     compartmentId: compartmentId,
 *     databaseDetails: {
 *         databaseType: targetDatabaseDatabaseDetailsDatabaseType,
 *         infrastructureType: targetDatabaseDatabaseDetailsInfrastructureType,
 *         autonomousDatabaseId: testAutonomousDatabase.id,
 *         dbSystemId: testDbSystem.id,
 *         instanceId: testInstance.id,
 *         ipAddresses: targetDatabaseDatabaseDetailsIpAddresses,
 *         listenerPort: targetDatabaseDatabaseDetailsListenerPort,
 *         serviceName: testService.name,
 *         vmClusterId: testVmCluster.id,
 *     },
 *     connectionOption: {
 *         connectionType: targetDatabaseConnectionOptionConnectionType,
 *         datasafePrivateEndpointId: testPrivateEndpoint.id,
 *         onPremConnectorId: testOnPremConnector.id,
 *     },
 *     credentials: {
 *         password: targetDatabaseCredentialsPassword,
 *         userName: testUser.name,
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: targetDatabaseDescription,
 *     displayName: targetDatabaseDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     peerTargetDatabaseDetails: [{
 *         databaseDetails: {
 *             databaseType: targetDatabasePeerTargetDatabaseDetailsDatabaseDetailsDatabaseType,
 *             infrastructureType: targetDatabasePeerTargetDatabaseDetailsDatabaseDetailsInfrastructureType,
 *             autonomousDatabaseId: testAutonomousDatabase.id,
 *             dbSystemId: testDbSystem.id,
 *             instanceId: testInstance.id,
 *             ipAddresses: targetDatabasePeerTargetDatabaseDetailsDatabaseDetailsIpAddresses,
 *             listenerPort: targetDatabasePeerTargetDatabaseDetailsDatabaseDetailsListenerPort,
 *             serviceName: testService.name,
 *             vmClusterId: testVmCluster.id,
 *         },
 *         dataguardAssociationId: testAssociation.id,
 *         description: targetDatabasePeerTargetDatabaseDetailsDescription,
 *         displayName: targetDatabasePeerTargetDatabaseDetailsDisplayName,
 *         tlsConfig: {
 *             status: targetDatabasePeerTargetDatabaseDetailsTlsConfigStatus,
 *             certificateStoreType: targetDatabasePeerTargetDatabaseDetailsTlsConfigCertificateStoreType,
 *             keyStoreContent: targetDatabasePeerTargetDatabaseDetailsTlsConfigKeyStoreContent,
 *             storePassword: targetDatabasePeerTargetDatabaseDetailsTlsConfigStorePassword,
 *             trustStoreContent: targetDatabasePeerTargetDatabaseDetailsTlsConfigTrustStoreContent,
 *         },
 *     }],
 *     tlsConfig: {
 *         status: targetDatabaseTlsConfigStatus,
 *         certificateStoreType: targetDatabaseTlsConfigCertificateStoreType,
 *         keyStoreContent: targetDatabaseTlsConfigKeyStoreContent,
 *         storePassword: targetDatabaseTlsConfigStorePassword,
 *         trustStoreContent: targetDatabaseTlsConfigTrustStoreContent,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * TargetDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataSafe/targetDatabase:TargetDatabase test_target_database "id"
 * ```
 */
export class TargetDatabase extends pulumi.CustomResource {
    /**
     * Get an existing TargetDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: TargetDatabaseState, opts?: pulumi.CustomResourceOptions): TargetDatabase {
        return new TargetDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/targetDatabase:TargetDatabase';

    /**
     * Returns true if the given object is an instance of TargetDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is TargetDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === TargetDatabase.__pulumiType;
    }

    /**
     * The OCIDs of associated resources like database, Data Safe private endpoint etc.
     */
    public /*out*/ readonly associatedResourceIds!: pulumi.Output<string[]>;
    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    public readonly connectionOption!: pulumi.Output<outputs.DataSafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    public readonly credentials!: pulumi.Output<outputs.DataSafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe.
     */
    public readonly databaseDetails!: pulumi.Output<outputs.DataSafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Details about the current state of the peer target database in Data Safe.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The details of the database to be registered as a peer target database.
     */
    public readonly peerTargetDatabaseDetails!: pulumi.Output<outputs.DataSafe.TargetDatabasePeerTargetDatabaseDetail[]>;
    /**
     * The OCIDs of associated resources like Database, Data Safe private endpoint etc.
     */
    public /*out*/ readonly peerTargetDatabases!: pulumi.Output<outputs.DataSafe.TargetDatabasePeerTargetDatabase[]>;
    /**
     * The current state of the target database in Data Safe.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time of the target database update in Data Safe.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    public readonly tlsConfig!: pulumi.Output<outputs.DataSafe.TargetDatabaseTlsConfig>;

    /**
     * Create a TargetDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: TargetDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: TargetDatabaseArgs | TargetDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as TargetDatabaseState | undefined;
            resourceInputs["associatedResourceIds"] = state ? state.associatedResourceIds : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionOption"] = state ? state.connectionOption : undefined;
            resourceInputs["credentials"] = state ? state.credentials : undefined;
            resourceInputs["databaseDetails"] = state ? state.databaseDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["peerTargetDatabaseDetails"] = state ? state.peerTargetDatabaseDetails : undefined;
            resourceInputs["peerTargetDatabases"] = state ? state.peerTargetDatabases : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["tlsConfig"] = state ? state.tlsConfig : undefined;
        } else {
            const args = argsOrState as TargetDatabaseArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.databaseDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'databaseDetails'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["connectionOption"] = args ? args.connectionOption : undefined;
            resourceInputs["credentials"] = args ? args.credentials : undefined;
            resourceInputs["databaseDetails"] = args ? args.databaseDetails : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["peerTargetDatabaseDetails"] = args ? args.peerTargetDatabaseDetails : undefined;
            resourceInputs["tlsConfig"] = args ? args.tlsConfig : undefined;
            resourceInputs["associatedResourceIds"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["peerTargetDatabases"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(TargetDatabase.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering TargetDatabase resources.
 */
export interface TargetDatabaseState {
    /**
     * The OCIDs of associated resources like database, Data Safe private endpoint etc.
     */
    associatedResourceIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    connectionOption?: pulumi.Input<inputs.DataSafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    credentials?: pulumi.Input<inputs.DataSafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe.
     */
    databaseDetails?: pulumi.Input<inputs.DataSafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Details about the current state of the peer target database in Data Safe.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The details of the database to be registered as a peer target database.
     */
    peerTargetDatabaseDetails?: pulumi.Input<pulumi.Input<inputs.DataSafe.TargetDatabasePeerTargetDatabaseDetail>[]>;
    /**
     * The OCIDs of associated resources like Database, Data Safe private endpoint etc.
     */
    peerTargetDatabases?: pulumi.Input<pulumi.Input<inputs.DataSafe.TargetDatabasePeerTargetDatabase>[]>;
    /**
     * The current state of the target database in Data Safe.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time of the target database update in Data Safe.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    tlsConfig?: pulumi.Input<inputs.DataSafe.TargetDatabaseTlsConfig>;
}

/**
 * The set of arguments for constructing a TargetDatabase resource.
 */
export interface TargetDatabaseArgs {
    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    connectionOption?: pulumi.Input<inputs.DataSafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    credentials?: pulumi.Input<inputs.DataSafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe.
     */
    databaseDetails: pulumi.Input<inputs.DataSafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The details of the database to be registered as a peer target database.
     */
    peerTargetDatabaseDetails?: pulumi.Input<pulumi.Input<inputs.DataSafe.TargetDatabasePeerTargetDatabaseDetail>[]>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    tlsConfig?: pulumi.Input<inputs.DataSafe.TargetDatabaseTlsConfig>;
}
