// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Databases Change Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Changes database parameter values. There are two kinds of database
 * parameters:
 *
 * - Dynamic parameters: They can be changed for the current Oracle
 *   Database instance. The changes take effect immediately.
 * - Static parameters: They cannot be changed for the current instance.
 *   You must change these parameters and then restart the database before
 *   changes take effect.
 *
 * **Note:** If the instance is started using a text initialization
 * parameter file, the parameter changes are applicable only for the
 * current instance. You must update them manually to be passed to
 * a future instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabasesChangeDatabaseParameter = new oci.databasemanagement.ManagedDatabasesChangeDatabaseParameter("test_managed_databases_change_database_parameter", {
 *     managedDatabaseId: testManagedDatabase.id,
 *     parameters: [{
 *         name: managedDatabasesChangeDatabaseParameterParametersName,
 *         value: managedDatabasesChangeDatabaseParameterParametersValue,
 *         updateComment: managedDatabasesChangeDatabaseParameterParametersUpdateComment,
 *     }],
 *     scope: managedDatabasesChangeDatabaseParameterScope,
 *     credentials: {
 *         password: managedDatabasesChangeDatabaseParameterCredentialsPassword,
 *         role: managedDatabasesChangeDatabaseParameterCredentialsRole,
 *         secretId: testSecret.id,
 *         userName: testUser.name,
 *     },
 *     databaseCredential: {
 *         credentialType: managedDatabasesChangeDatabaseParameterDatabaseCredentialCredentialType,
 *         namedCredentialId: testNamedCredential.id,
 *         password: managedDatabasesChangeDatabaseParameterDatabaseCredentialPassword,
 *         passwordSecretId: testSecret.id,
 *         role: managedDatabasesChangeDatabaseParameterDatabaseCredentialRole,
 *         username: managedDatabasesChangeDatabaseParameterDatabaseCredentialUsername,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class ManagedDatabasesChangeDatabaseParameter extends pulumi.CustomResource {
    /**
     * Get an existing ManagedDatabasesChangeDatabaseParameter resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedDatabasesChangeDatabaseParameterState, opts?: pulumi.CustomResourceOptions): ManagedDatabasesChangeDatabaseParameter {
        return new ManagedDatabasesChangeDatabaseParameter(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter';

    /**
     * Returns true if the given object is an instance of ManagedDatabasesChangeDatabaseParameter.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedDatabasesChangeDatabaseParameter {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedDatabasesChangeDatabaseParameter.__pulumiType;
    }

    /**
     * The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
     */
    public readonly credentials!: pulumi.Output<outputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterCredentials>;
    /**
     * The credential to connect to the database to perform tablespace administration tasks.
     */
    public readonly databaseCredential!: pulumi.Output<outputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterDatabaseCredential>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    public readonly managedDatabaseId!: pulumi.Output<string>;
    /**
     * A list of database parameters and their values.
     */
    public readonly parameters!: pulumi.Output<outputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterParameter[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     *
     * Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly scope!: pulumi.Output<string>;

    /**
     * Create a ManagedDatabasesChangeDatabaseParameter resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedDatabasesChangeDatabaseParameterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedDatabasesChangeDatabaseParameterArgs | ManagedDatabasesChangeDatabaseParameterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedDatabasesChangeDatabaseParameterState | undefined;
            resourceInputs["credentials"] = state ? state.credentials : undefined;
            resourceInputs["databaseCredential"] = state ? state.databaseCredential : undefined;
            resourceInputs["managedDatabaseId"] = state ? state.managedDatabaseId : undefined;
            resourceInputs["parameters"] = state ? state.parameters : undefined;
            resourceInputs["scope"] = state ? state.scope : undefined;
        } else {
            const args = argsOrState as ManagedDatabasesChangeDatabaseParameterArgs | undefined;
            if ((!args || args.managedDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedDatabaseId'");
            }
            if ((!args || args.parameters === undefined) && !opts.urn) {
                throw new Error("Missing required property 'parameters'");
            }
            if ((!args || args.scope === undefined) && !opts.urn) {
                throw new Error("Missing required property 'scope'");
            }
            resourceInputs["credentials"] = args ? args.credentials : undefined;
            resourceInputs["databaseCredential"] = args ? args.databaseCredential : undefined;
            resourceInputs["managedDatabaseId"] = args ? args.managedDatabaseId : undefined;
            resourceInputs["parameters"] = args ? args.parameters : undefined;
            resourceInputs["scope"] = args ? args.scope : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ManagedDatabasesChangeDatabaseParameter.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedDatabasesChangeDatabaseParameter resources.
 */
export interface ManagedDatabasesChangeDatabaseParameterState {
    /**
     * The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
     */
    credentials?: pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterCredentials>;
    /**
     * The credential to connect to the database to perform tablespace administration tasks.
     */
    databaseCredential?: pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterDatabaseCredential>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId?: pulumi.Input<string>;
    /**
     * A list of database parameters and their values.
     */
    parameters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterParameter>[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     *
     * Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    scope?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ManagedDatabasesChangeDatabaseParameter resource.
 */
export interface ManagedDatabasesChangeDatabaseParameterArgs {
    /**
     * The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
     */
    credentials?: pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterCredentials>;
    /**
     * The credential to connect to the database to perform tablespace administration tasks.
     */
    databaseCredential?: pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterDatabaseCredential>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * A list of database parameters and their values.
     */
    parameters: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterParameter>[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     *
     * Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    scope: pulumi.Input<string>;
}
