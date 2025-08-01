// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Oracle Db Azure Connector resource in Oracle Cloud Infrastructure Dbmulticloud service.
 *
 * Creates Oracle DB Azure Connector Resource and configured Azure Identity in Oracle Cloud Infrastructure Database Resource.
 *
 *   Patch Azure Arc Agent on VM Cluster with new version.
 *
 * ## Import
 *
 * OracleDbAzureConnectors can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:oci/dbmulticloudOracleDbAzureConnector:DbmulticloudOracleDbAzureConnector test_oracle_db_azure_connector "id"
 * ```
 */
export class DbmulticloudOracleDbAzureConnector extends pulumi.CustomResource {
    /**
     * Get an existing DbmulticloudOracleDbAzureConnector resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DbmulticloudOracleDbAzureConnectorState, opts?: pulumi.CustomResourceOptions): DbmulticloudOracleDbAzureConnector {
        return new DbmulticloudOracleDbAzureConnector(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:oci/dbmulticloudOracleDbAzureConnector:DbmulticloudOracleDbAzureConnector';

    /**
     * Returns true if the given object is an instance of DbmulticloudOracleDbAzureConnector.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DbmulticloudOracleDbAzureConnector {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DbmulticloudOracleDbAzureConnector.__pulumiType;
    }

    /**
     * (Updatable) Azure bearer access token. If bearer access token is provided then Service Principal details are not requires.
     */
    public readonly accessToken!: pulumi.Output<string>;
    /**
     * List of All VMs where Arc Agent is Install under VMCluster.
     */
    public readonly arcAgentNodes!: pulumi.Output<outputs.oci.DbmulticloudOracleDbAzureConnectorArcAgentNode[]>;
    /**
     * (Updatable) Azure Identity Mechanism.
     */
    public readonly azureIdentityMechanism!: pulumi.Output<string>;
    /**
     * (Updatable) Azure Resource Group Name.
     */
    public readonly azureResourceGroup!: pulumi.Output<string>;
    /**
     * (Updatable) Azure Subscription ID.
     */
    public readonly azureSubscriptionId!: pulumi.Output<string>;
    /**
     * (Updatable) Azure Tenant ID.
     */
    public readonly azureTenantId!: pulumi.Output<string>;
    /**
     * (Updatable) The ID of the compartment that contains Oracle DB Azure Connector Resource.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The ID of the DB Cluster Resource where this Azure Arc Agent Identity to configure.
     */
    public readonly dbClusterResourceId!: pulumi.Output<string>;
    /**
     * (Updatable) Oracle DB Azure Connector Resource name.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Description of the latest modification of the Oracle DB Azure Connector Resource.
     */
    public readonly lastModification!: pulumi.Output<string>;
    /**
     * Description of the current lifecycle state in more detail.
     */
    public readonly lifecycleStateDetails!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the Azure Arc Agent Resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Time when the Oracle DB Azure Connector Resource was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time when the Oracle DB Azure Connector Resource was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DbmulticloudOracleDbAzureConnector resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DbmulticloudOracleDbAzureConnectorArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DbmulticloudOracleDbAzureConnectorArgs | DbmulticloudOracleDbAzureConnectorState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DbmulticloudOracleDbAzureConnectorState | undefined;
            resourceInputs["accessToken"] = state ? state.accessToken : undefined;
            resourceInputs["arcAgentNodes"] = state ? state.arcAgentNodes : undefined;
            resourceInputs["azureIdentityMechanism"] = state ? state.azureIdentityMechanism : undefined;
            resourceInputs["azureResourceGroup"] = state ? state.azureResourceGroup : undefined;
            resourceInputs["azureSubscriptionId"] = state ? state.azureSubscriptionId : undefined;
            resourceInputs["azureTenantId"] = state ? state.azureTenantId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dbClusterResourceId"] = state ? state.dbClusterResourceId : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["lastModification"] = state ? state.lastModification : undefined;
            resourceInputs["lifecycleStateDetails"] = state ? state.lifecycleStateDetails : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DbmulticloudOracleDbAzureConnectorArgs | undefined;
            if ((!args || args.accessToken === undefined) && !opts.urn) {
                throw new Error("Missing required property 'accessToken'");
            }
            if ((!args || args.azureIdentityMechanism === undefined) && !opts.urn) {
                throw new Error("Missing required property 'azureIdentityMechanism'");
            }
            if ((!args || args.azureResourceGroup === undefined) && !opts.urn) {
                throw new Error("Missing required property 'azureResourceGroup'");
            }
            if ((!args || args.azureSubscriptionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'azureSubscriptionId'");
            }
            if ((!args || args.azureTenantId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'azureTenantId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.dbClusterResourceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dbClusterResourceId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["accessToken"] = args ? args.accessToken : undefined;
            resourceInputs["arcAgentNodes"] = args ? args.arcAgentNodes : undefined;
            resourceInputs["azureIdentityMechanism"] = args ? args.azureIdentityMechanism : undefined;
            resourceInputs["azureResourceGroup"] = args ? args.azureResourceGroup : undefined;
            resourceInputs["azureSubscriptionId"] = args ? args.azureSubscriptionId : undefined;
            resourceInputs["azureTenantId"] = args ? args.azureTenantId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dbClusterResourceId"] = args ? args.dbClusterResourceId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["lastModification"] = args ? args.lastModification : undefined;
            resourceInputs["lifecycleStateDetails"] = args ? args.lifecycleStateDetails : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DbmulticloudOracleDbAzureConnector.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DbmulticloudOracleDbAzureConnector resources.
 */
export interface DbmulticloudOracleDbAzureConnectorState {
    /**
     * (Updatable) Azure bearer access token. If bearer access token is provided then Service Principal details are not requires.
     */
    accessToken?: pulumi.Input<string>;
    /**
     * List of All VMs where Arc Agent is Install under VMCluster.
     */
    arcAgentNodes?: pulumi.Input<pulumi.Input<inputs.oci.DbmulticloudOracleDbAzureConnectorArcAgentNode>[]>;
    /**
     * (Updatable) Azure Identity Mechanism.
     */
    azureIdentityMechanism?: pulumi.Input<string>;
    /**
     * (Updatable) Azure Resource Group Name.
     */
    azureResourceGroup?: pulumi.Input<string>;
    /**
     * (Updatable) Azure Subscription ID.
     */
    azureSubscriptionId?: pulumi.Input<string>;
    /**
     * (Updatable) Azure Tenant ID.
     */
    azureTenantId?: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the compartment that contains Oracle DB Azure Connector Resource.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the DB Cluster Resource where this Azure Arc Agent Identity to configure.
     */
    dbClusterResourceId?: pulumi.Input<string>;
    /**
     * (Updatable) Oracle DB Azure Connector Resource name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Description of the latest modification of the Oracle DB Azure Connector Resource.
     */
    lastModification?: pulumi.Input<string>;
    /**
     * Description of the current lifecycle state in more detail.
     */
    lifecycleStateDetails?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the Azure Arc Agent Resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Time when the Oracle DB Azure Connector Resource was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time when the Oracle DB Azure Connector Resource was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DbmulticloudOracleDbAzureConnector resource.
 */
export interface DbmulticloudOracleDbAzureConnectorArgs {
    /**
     * (Updatable) Azure bearer access token. If bearer access token is provided then Service Principal details are not requires.
     */
    accessToken: pulumi.Input<string>;
    /**
     * List of All VMs where Arc Agent is Install under VMCluster.
     */
    arcAgentNodes?: pulumi.Input<pulumi.Input<inputs.oci.DbmulticloudOracleDbAzureConnectorArcAgentNode>[]>;
    /**
     * (Updatable) Azure Identity Mechanism.
     */
    azureIdentityMechanism: pulumi.Input<string>;
    /**
     * (Updatable) Azure Resource Group Name.
     */
    azureResourceGroup: pulumi.Input<string>;
    /**
     * (Updatable) Azure Subscription ID.
     */
    azureSubscriptionId: pulumi.Input<string>;
    /**
     * (Updatable) Azure Tenant ID.
     */
    azureTenantId: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the compartment that contains Oracle DB Azure Connector Resource.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The ID of the DB Cluster Resource where this Azure Arc Agent Identity to configure.
     */
    dbClusterResourceId: pulumi.Input<string>;
    /**
     * (Updatable) Oracle DB Azure Connector Resource name.
     */
    displayName: pulumi.Input<string>;
    /**
     * Description of the latest modification of the Oracle DB Azure Connector Resource.
     */
    lastModification?: pulumi.Input<string>;
    /**
     * Description of the current lifecycle state in more detail.
     */
    lifecycleStateDetails?: pulumi.Input<string>;
}
