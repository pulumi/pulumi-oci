// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Db Management Private Endpoint resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Creates a new Database Management private endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbManagementPrivateEndpoint = new oci.databasemanagement.DbManagementPrivateEndpoint("testDbManagementPrivateEndpoint", {
 *     compartmentId: _var.compartment_id,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     description: _var.db_management_private_endpoint_description,
 *     isCluster: _var.db_management_private_endpoint_is_cluster,
 *     nsgIds: _var.db_management_private_endpoint_nsg_ids,
 * });
 * ```
 *
 * ## Import
 *
 * DbManagementPrivateEndpoints can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint test_db_management_private_endpoint "id"
 * ```
 */
export class DbManagementPrivateEndpoint extends pulumi.CustomResource {
    /**
     * Get an existing DbManagementPrivateEndpoint resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DbManagementPrivateEndpointState, opts?: pulumi.CustomResourceOptions): DbManagementPrivateEndpoint {
        return new DbManagementPrivateEndpoint(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint';

    /**
     * Returns true if the given object is an instance of DbManagementPrivateEndpoint.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DbManagementPrivateEndpoint {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DbManagementPrivateEndpoint.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The description of the private endpoint.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
     */
    public readonly isCluster!: pulumi.Output<boolean>;
    /**
     * (Updatable) The display name of the Database Management private endpoint.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The IP addresses assigned to the Database Management private endpoint.
     */
    public /*out*/ readonly privateIp!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the Database Management private endpoint.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    public /*out*/ readonly vcnId!: pulumi.Output<string>;

    /**
     * Create a DbManagementPrivateEndpoint resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DbManagementPrivateEndpointArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DbManagementPrivateEndpointArgs | DbManagementPrivateEndpointState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DbManagementPrivateEndpointState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["isCluster"] = state ? state.isCluster : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["privateIp"] = state ? state.privateIp : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["vcnId"] = state ? state.vcnId : undefined;
        } else {
            const args = argsOrState as DbManagementPrivateEndpointArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["isCluster"] = args ? args.isCluster : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["privateIp"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["vcnId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DbManagementPrivateEndpoint.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DbManagementPrivateEndpoint resources.
 */
export interface DbManagementPrivateEndpointState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The description of the private endpoint.
     */
    description?: pulumi.Input<string>;
    /**
     * Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
     */
    isCluster?: pulumi.Input<boolean>;
    /**
     * (Updatable) The display name of the Database Management private endpoint.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The IP addresses assigned to the Database Management private endpoint.
     */
    privateIp?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the Database Management private endpoint.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DbManagementPrivateEndpoint resource.
 */
export interface DbManagementPrivateEndpointArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The description of the private endpoint.
     */
    description?: pulumi.Input<string>;
    /**
     * Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
     */
    isCluster?: pulumi.Input<boolean>;
    /**
     * (Updatable) The display name of the Database Management private endpoint.
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     */
    subnetId: pulumi.Input<string>;
}