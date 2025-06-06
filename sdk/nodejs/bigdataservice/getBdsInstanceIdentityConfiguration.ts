// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Bds Instance Identity Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Get details of one identity config on the cluster
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceIdentityConfiguration = oci.BigDataService.getBdsInstanceIdentityConfiguration({
 *     bdsInstanceId: testBdsInstance.id,
 *     identityConfigurationId: testConfiguration.id,
 * });
 * ```
 */
export function getBdsInstanceIdentityConfiguration(args: GetBdsInstanceIdentityConfigurationArgs, opts?: pulumi.InvokeOptions): Promise<GetBdsInstanceIdentityConfigurationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:BigDataService/getBdsInstanceIdentityConfiguration:getBdsInstanceIdentityConfiguration", {
        "bdsInstanceId": args.bdsInstanceId,
        "identityConfigurationId": args.identityConfigurationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstanceIdentityConfiguration.
 */
export interface GetBdsInstanceIdentityConfigurationArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: string;
    /**
     * The OCID of the identity configuration
     */
    identityConfigurationId: string;
}

/**
 * A collection of values returned by getBdsInstanceIdentityConfiguration.
 */
export interface GetBdsInstanceIdentityConfigurationResult {
    readonly activateIamUserSyncConfigurationTrigger: string;
    readonly activateUpstConfigurationTrigger: string;
    readonly bdsInstanceId: string;
    readonly clusterAdminPassword: string;
    /**
     * identity domain confidential application ID for the identity config
     */
    readonly confidentialApplicationId: string;
    /**
     * the display name of the identity configuration
     */
    readonly displayName: string;
    readonly iamUserSyncConfigurationDetails: outputs.BigDataService.GetBdsInstanceIdentityConfigurationIamUserSyncConfigurationDetail[];
    /**
     * Information about the IAM user sync configuration.
     */
    readonly iamUserSyncConfigurations: outputs.BigDataService.GetBdsInstanceIdentityConfigurationIamUserSyncConfiguration[];
    /**
     * The id of the identity config
     */
    readonly id: string;
    readonly identityConfigurationId: string;
    /**
     * Identity domain to use for identity config
     */
    readonly identityDomainId: string;
    readonly refreshConfidentialApplicationTrigger: string;
    readonly refreshUpstTokenExchangeKeytabTrigger: string;
    /**
     * Lifecycle state of the UPST config
     */
    readonly state: string;
    /**
     * Time when this UPST config was created, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * Time when this UPST config was updated, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly upstConfigurationDetails: outputs.BigDataService.GetBdsInstanceIdentityConfigurationUpstConfigurationDetail[];
    /**
     * Information about the UPST configuration.
     */
    readonly upstConfigurations: outputs.BigDataService.GetBdsInstanceIdentityConfigurationUpstConfiguration[];
}
/**
 * This data source provides details about a specific Bds Instance Identity Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Get details of one identity config on the cluster
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceIdentityConfiguration = oci.BigDataService.getBdsInstanceIdentityConfiguration({
 *     bdsInstanceId: testBdsInstance.id,
 *     identityConfigurationId: testConfiguration.id,
 * });
 * ```
 */
export function getBdsInstanceIdentityConfigurationOutput(args: GetBdsInstanceIdentityConfigurationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBdsInstanceIdentityConfigurationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:BigDataService/getBdsInstanceIdentityConfiguration:getBdsInstanceIdentityConfiguration", {
        "bdsInstanceId": args.bdsInstanceId,
        "identityConfigurationId": args.identityConfigurationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstanceIdentityConfiguration.
 */
export interface GetBdsInstanceIdentityConfigurationOutputArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
    /**
     * The OCID of the identity configuration
     */
    identityConfigurationId: pulumi.Input<string>;
}
