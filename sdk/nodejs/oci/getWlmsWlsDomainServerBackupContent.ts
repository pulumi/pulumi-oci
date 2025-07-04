// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Wls Domain Server Backup Content resource in Oracle Cloud Infrastructure Wlms service.
 *
 * Get details of specific backup for the WebLogic Domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWlsDomainServerBackupContent = oci.oci.getWlmsWlsDomainServerBackupContent({
 *     backupId: testBackup.id,
 *     serverId: testServer.id,
 *     wlsDomainId: testWlsDomain.id,
 * });
 * ```
 */
export function getWlmsWlsDomainServerBackupContent(args: GetWlmsWlsDomainServerBackupContentArgs, opts?: pulumi.InvokeOptions): Promise<GetWlmsWlsDomainServerBackupContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:oci/getWlmsWlsDomainServerBackupContent:getWlmsWlsDomainServerBackupContent", {
        "backupId": args.backupId,
        "serverId": args.serverId,
        "wlsDomainId": args.wlsDomainId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWlmsWlsDomainServerBackupContent.
 */
export interface GetWlmsWlsDomainServerBackupContentArgs {
    /**
     * The unique identifier of the backup.
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    backupId: string;
    /**
     * The unique identifier of a server.
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    serverId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     */
    wlsDomainId: string;
}

/**
 * A collection of values returned by getWlmsWlsDomainServerBackupContent.
 */
export interface GetWlmsWlsDomainServerBackupContentResult {
    readonly backupId: string;
    /**
     * The type of content of the backup.
     */
    readonly contentType: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The content of the middleware binaries included in a backup.
     */
    readonly middlewares: outputs.oci.GetWlmsWlsDomainServerBackupContentMiddleware[];
    readonly serverId: string;
    readonly wlsDomainId: string;
}
/**
 * This data source provides details about a specific Wls Domain Server Backup Content resource in Oracle Cloud Infrastructure Wlms service.
 *
 * Get details of specific backup for the WebLogic Domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWlsDomainServerBackupContent = oci.oci.getWlmsWlsDomainServerBackupContent({
 *     backupId: testBackup.id,
 *     serverId: testServer.id,
 *     wlsDomainId: testWlsDomain.id,
 * });
 * ```
 */
export function getWlmsWlsDomainServerBackupContentOutput(args: GetWlmsWlsDomainServerBackupContentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetWlmsWlsDomainServerBackupContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:oci/getWlmsWlsDomainServerBackupContent:getWlmsWlsDomainServerBackupContent", {
        "backupId": args.backupId,
        "serverId": args.serverId,
        "wlsDomainId": args.wlsDomainId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWlmsWlsDomainServerBackupContent.
 */
export interface GetWlmsWlsDomainServerBackupContentOutputArgs {
    /**
     * The unique identifier of the backup.
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    backupId: pulumi.Input<string>;
    /**
     * The unique identifier of a server.
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    serverId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     */
    wlsDomainId: pulumi.Input<string>;
}
