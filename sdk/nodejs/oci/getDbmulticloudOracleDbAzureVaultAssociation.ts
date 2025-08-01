// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Oracle Db Azure Vault Association resource in Oracle Cloud Infrastructure Dbmulticloud service.
 *
 * Get Oracle DB Azure Vault Details Association form a particular Container Resource ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOracleDbAzureVaultAssociation = oci.oci.getDbmulticloudOracleDbAzureVaultAssociation({
 *     oracleDbAzureVaultAssociationId: testOracleDbAzureVaultAssociationOciDbmulticloudOracleDbAzureVaultAssociation.id,
 * });
 * ```
 */
export function getDbmulticloudOracleDbAzureVaultAssociation(args: GetDbmulticloudOracleDbAzureVaultAssociationArgs, opts?: pulumi.InvokeOptions): Promise<GetDbmulticloudOracleDbAzureVaultAssociationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:oci/getDbmulticloudOracleDbAzureVaultAssociation:getDbmulticloudOracleDbAzureVaultAssociation", {
        "oracleDbAzureVaultAssociationId": args.oracleDbAzureVaultAssociationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbmulticloudOracleDbAzureVaultAssociation.
 */
export interface GetDbmulticloudOracleDbAzureVaultAssociationArgs {
    /**
     * The ID of the Oracle DB Azure Vault Association Resource.
     */
    oracleDbAzureVaultAssociationId: string;
}

/**
 * A collection of values returned by getDbmulticloudOracleDbAzureVaultAssociation.
 */
export interface GetDbmulticloudOracleDbAzureVaultAssociationResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Oracle DB Azure Vault Association Resource.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Display name of Oracle DB Azure Vault Association.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle DB Azure Vault Association Resource.
     */
    readonly id: string;
    /**
     * The Associated Resources are accessible or not.
     */
    readonly isResourceAccessible: boolean;
    /**
     * Description of the latest modification of the Oracle DB Azure Vault Association Resource.
     */
    readonly lastModification: string;
    /**
     * Description of the current lifecycle state in more detail.
     */
    readonly lifecycleStateDetails: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle DB Azure Connector.
     */
    readonly oracleDbAzureConnectorId: string;
    readonly oracleDbAzureVaultAssociationId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle DB Azure Vault.
     */
    readonly oracleDbAzureVaultId: string;
    /**
     * The current lifecycle state of the Oracle DB Azure Vault Association Resource.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Time when the Oracle DB Azure Vault Association was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    readonly timeCreated: string;
    /**
     * Time when the Oracle DB Azure Vault Association was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Oracle Db Azure Vault Association resource in Oracle Cloud Infrastructure Dbmulticloud service.
 *
 * Get Oracle DB Azure Vault Details Association form a particular Container Resource ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOracleDbAzureVaultAssociation = oci.oci.getDbmulticloudOracleDbAzureVaultAssociation({
 *     oracleDbAzureVaultAssociationId: testOracleDbAzureVaultAssociationOciDbmulticloudOracleDbAzureVaultAssociation.id,
 * });
 * ```
 */
export function getDbmulticloudOracleDbAzureVaultAssociationOutput(args: GetDbmulticloudOracleDbAzureVaultAssociationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbmulticloudOracleDbAzureVaultAssociationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:oci/getDbmulticloudOracleDbAzureVaultAssociation:getDbmulticloudOracleDbAzureVaultAssociation", {
        "oracleDbAzureVaultAssociationId": args.oracleDbAzureVaultAssociationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbmulticloudOracleDbAzureVaultAssociation.
 */
export interface GetDbmulticloudOracleDbAzureVaultAssociationOutputArgs {
    /**
     * The ID of the Oracle DB Azure Vault Association Resource.
     */
    oracleDbAzureVaultAssociationId: pulumi.Input<string>;
}
