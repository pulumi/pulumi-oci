// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Database Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Enable / Update / Disable database management for the specified Oracle Database instance.
 *
 * Database Management requires `USER_NAME`, `PASSWORD_SECRET_ID` and `PRIVATE_END_POINT_ID`.
 * `database.0.database_management_config` is updated to appropriate managementType and managementStatus for the specified Oracle Database instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const test = new oci.database.CloudDatabaseManagement("test", {
 *     databaseId: oci_database_database.test_database.id,
 *     managementType: _var.database_cloud_database_management_details_management_type,
 *     privateEndPointId: _var.database_cloud_database_management_details_private_end_point_id,
 *     serviceName: _var.database_cloud_database_management_details_service_name,
 *     credentialdetails: {
 *         userName: _var.database_cloud_database_management_details_user_name,
 *         passwordSecretId: _var.database_cloud_database_management_details_password_secret_id,
 *     },
 *     enableManagement: _var.database_cloud_database_management_details_enable_management,
 *     port: _var.cloud_database_management_port,
 *     protocol: _var.cloud_database_management_protocol,
 *     role: _var.cloud_database_management_role,
 *     sslSecretId: oci_vault_secret.test_secret.id,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class CloudDatabaseManagement extends pulumi.CustomResource {
    /**
     * Get an existing CloudDatabaseManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CloudDatabaseManagementState, opts?: pulumi.CustomResourceOptions): CloudDatabaseManagement {
        return new CloudDatabaseManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/cloudDatabaseManagement:CloudDatabaseManagement';

    /**
     * Returns true if the given object is an instance of CloudDatabaseManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CloudDatabaseManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CloudDatabaseManagement.__pulumiType;
    }

    public readonly credentialdetails!: pulumi.Output<outputs.Database.CloudDatabaseManagementCredentialdetails>;
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly databaseId!: pulumi.Output<string>;
    /**
     * (Updatable) Use this flag to enable/disable database management
     */
    public readonly enableManagement!: pulumi.Output<boolean>;
    /**
     * (Updatable) Specifies database management type
     * enum:
     * - `BASIC`
     * - `ADVANCED`
     */
    public readonly managementType!: pulumi.Output<string>;
    /**
     * The port used to connect to the database.
     */
    public readonly port!: pulumi.Output<number | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     */
    public readonly privateEndPointId!: pulumi.Output<string>;
    /**
     * Protocol used by the database connection.
     */
    public readonly protocol!: pulumi.Output<string | undefined>;
    /**
     * The role of the user that will be connecting to the database.
     */
    public readonly role!: pulumi.Output<string | undefined>;
    /**
     * The name of the Oracle Database service that will be used to connect to the database.
     */
    public readonly serviceName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    public readonly sslSecretId!: pulumi.Output<string | undefined>;

    /**
     * Create a CloudDatabaseManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CloudDatabaseManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CloudDatabaseManagementArgs | CloudDatabaseManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CloudDatabaseManagementState | undefined;
            resourceInputs["credentialdetails"] = state ? state.credentialdetails : undefined;
            resourceInputs["databaseId"] = state ? state.databaseId : undefined;
            resourceInputs["enableManagement"] = state ? state.enableManagement : undefined;
            resourceInputs["managementType"] = state ? state.managementType : undefined;
            resourceInputs["port"] = state ? state.port : undefined;
            resourceInputs["privateEndPointId"] = state ? state.privateEndPointId : undefined;
            resourceInputs["protocol"] = state ? state.protocol : undefined;
            resourceInputs["role"] = state ? state.role : undefined;
            resourceInputs["serviceName"] = state ? state.serviceName : undefined;
            resourceInputs["sslSecretId"] = state ? state.sslSecretId : undefined;
        } else {
            const args = argsOrState as CloudDatabaseManagementArgs | undefined;
            if ((!args || args.credentialdetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'credentialdetails'");
            }
            if ((!args || args.databaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'databaseId'");
            }
            if ((!args || args.enableManagement === undefined) && !opts.urn) {
                throw new Error("Missing required property 'enableManagement'");
            }
            if ((!args || args.managementType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managementType'");
            }
            if ((!args || args.privateEndPointId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'privateEndPointId'");
            }
            if ((!args || args.serviceName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'serviceName'");
            }
            resourceInputs["credentialdetails"] = args ? args.credentialdetails : undefined;
            resourceInputs["databaseId"] = args ? args.databaseId : undefined;
            resourceInputs["enableManagement"] = args ? args.enableManagement : undefined;
            resourceInputs["managementType"] = args ? args.managementType : undefined;
            resourceInputs["port"] = args ? args.port : undefined;
            resourceInputs["privateEndPointId"] = args ? args.privateEndPointId : undefined;
            resourceInputs["protocol"] = args ? args.protocol : undefined;
            resourceInputs["role"] = args ? args.role : undefined;
            resourceInputs["serviceName"] = args ? args.serviceName : undefined;
            resourceInputs["sslSecretId"] = args ? args.sslSecretId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CloudDatabaseManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CloudDatabaseManagement resources.
 */
export interface CloudDatabaseManagementState {
    credentialdetails?: pulumi.Input<inputs.Database.CloudDatabaseManagementCredentialdetails>;
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    databaseId?: pulumi.Input<string>;
    /**
     * (Updatable) Use this flag to enable/disable database management
     */
    enableManagement?: pulumi.Input<boolean>;
    /**
     * (Updatable) Specifies database management type
     * enum:
     * - `BASIC`
     * - `ADVANCED`
     */
    managementType?: pulumi.Input<string>;
    /**
     * The port used to connect to the database.
     */
    port?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     */
    privateEndPointId?: pulumi.Input<string>;
    /**
     * Protocol used by the database connection.
     */
    protocol?: pulumi.Input<string>;
    /**
     * The role of the user that will be connecting to the database.
     */
    role?: pulumi.Input<string>;
    /**
     * The name of the Oracle Database service that will be used to connect to the database.
     */
    serviceName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    sslSecretId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a CloudDatabaseManagement resource.
 */
export interface CloudDatabaseManagementArgs {
    credentialdetails: pulumi.Input<inputs.Database.CloudDatabaseManagementCredentialdetails>;
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    databaseId: pulumi.Input<string>;
    /**
     * (Updatable) Use this flag to enable/disable database management
     */
    enableManagement: pulumi.Input<boolean>;
    /**
     * (Updatable) Specifies database management type
     * enum:
     * - `BASIC`
     * - `ADVANCED`
     */
    managementType: pulumi.Input<string>;
    /**
     * The port used to connect to the database.
     */
    port?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     */
    privateEndPointId: pulumi.Input<string>;
    /**
     * Protocol used by the database connection.
     */
    protocol?: pulumi.Input<string>;
    /**
     * The role of the user that will be connecting to the database.
     */
    role?: pulumi.Input<string>;
    /**
     * The name of the Oracle Database service that will be used to connect to the database.
     */
    serviceName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    sslSecretId?: pulumi.Input<string>;
}