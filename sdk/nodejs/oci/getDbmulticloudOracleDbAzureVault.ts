// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Oracle Db Azure Vault resource in Oracle Cloud Infrastructure Dbmulticloud service.
 *
 * Get Oracle DB Azure Vault Details form a particular Container Resource ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOracleDbAzureVault = oci.oci.getDbmulticloudOracleDbAzureVault({
 *     oracleDbAzureVaultId: testOracleDbAzureVaultOciDbmulticloudOracleDbAzureVault.id,
 * });
 * ```
 */
export function getDbmulticloudOracleDbAzureVault(args: GetDbmulticloudOracleDbAzureVaultArgs, opts?: pulumi.InvokeOptions): Promise<GetDbmulticloudOracleDbAzureVaultResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:oci/getDbmulticloudOracleDbAzureVault:getDbmulticloudOracleDbAzureVault", {
        "oracleDbAzureVaultId": args.oracleDbAzureVaultId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbmulticloudOracleDbAzureVault.
 */
export interface GetDbmulticloudOracleDbAzureVaultArgs {
    /**
     * The ID of the Oracle DB Azure Vault Resource.
     */
    oracleDbAzureVaultId: string;
}

/**
 * A collection of values returned by getDbmulticloudOracleDbAzureVault.
 */
export interface GetDbmulticloudOracleDbAzureVaultResult {
    /**
     * Azure Vault Id.
     */
    readonly azureVaultId: string;
    /**
     * The Compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that has this DB Azure Vault Resource.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Display name of DB Azure Vault.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB Azure Vault Resource.
     */
    readonly id: string;
    /**
     * Description of the latest modification of the DB Azure Vault Resource.
     */
    readonly lastModification: string;
    /**
     * Description of the current lifecycle state in more detail.
     */
    readonly lifecycleStateDetails: string;
    /**
     * Vault Resource Location.
     */
    readonly location: string;
    /**
     * Display name of Azure Resource Group.
     */
    readonly oracleDbAzureResourceGroup: string;
    readonly oracleDbAzureVaultId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB Connector Resource.
     */
    readonly oracleDbConnectorId: string;
    /**
     * Resource's properties.
     */
    readonly properties: {[key: string]: string};
    /**
     * The lifecycle state of the DB Azure Vault Resource.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Time when the DB Azure Vault was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-23T21:10:29.600Z'
     */
    readonly timeCreated: string;
    /**
     * Time when the DB Azure Vault was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-23T21:10:29.600Z'
     */
    readonly timeUpdated: string;
    /**
     * Vault Resource Type.
     */
    readonly type: string;
}
/**
 * This data source provides details about a specific Oracle Db Azure Vault resource in Oracle Cloud Infrastructure Dbmulticloud service.
 *
 * Get Oracle DB Azure Vault Details form a particular Container Resource ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOracleDbAzureVault = oci.oci.getDbmulticloudOracleDbAzureVault({
 *     oracleDbAzureVaultId: testOracleDbAzureVaultOciDbmulticloudOracleDbAzureVault.id,
 * });
 * ```
 */
export function getDbmulticloudOracleDbAzureVaultOutput(args: GetDbmulticloudOracleDbAzureVaultOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbmulticloudOracleDbAzureVaultResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:oci/getDbmulticloudOracleDbAzureVault:getDbmulticloudOracleDbAzureVault", {
        "oracleDbAzureVaultId": args.oracleDbAzureVaultId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbmulticloudOracleDbAzureVault.
 */
export interface GetDbmulticloudOracleDbAzureVaultOutputArgs {
    /**
     * The ID of the Oracle DB Azure Vault Resource.
     */
    oracleDbAzureVaultId: pulumi.Input<string>;
}
