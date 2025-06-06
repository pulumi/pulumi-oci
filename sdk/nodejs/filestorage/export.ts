// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Export resource in Oracle Cloud Infrastructure File Storage service.
 *
 * Creates a new export in the specified export set, path, and
 * file system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExport = new oci.filestorage.Export("test_export", {
 *     exportSetId: testExportSet.id,
 *     fileSystemId: testFileSystem.id,
 *     path: exportPath,
 *     exportOptions: [{
 *         source: exportExportOptionsSource,
 *         access: exportExportOptionsAccess,
 *         allowedAuths: exportExportOptionsAllowedAuth,
 *         anonymousGid: exportExportOptionsAnonymousGid,
 *         anonymousUid: exportExportOptionsAnonymousUid,
 *         identitySquash: exportExportOptionsIdentitySquash,
 *         isAnonymousAccessAllowed: exportExportOptionsIsAnonymousAccessAllowed,
 *         requirePrivilegedSourcePort: exportExportOptionsRequirePrivilegedSourcePort,
 *     }],
 *     isIdmapGroupsForSysAuth: exportIsIdmapGroupsForSysAuth,
 *     locks: [{
 *         type: exportLocksType,
 *         message: exportLocksMessage,
 *         relatedResourceId: testResource.id,
 *         timeCreated: exportLocksTimeCreated,
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * Exports can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:FileStorage/export:Export test_export "id"
 * ```
 */
export class Export extends pulumi.CustomResource {
    /**
     * Get an existing Export resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExportState, opts?: pulumi.CustomResourceOptions): Export {
        return new Export(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FileStorage/export:Export';

    /**
     * Returns true if the given object is an instance of Export.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Export {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Export.__pulumiType;
    }

    /**
     * (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
     *
     * [ { "source" : "0.0.0.0/0", "requirePrivilegedSourcePort" : false, "access": "READ_WRITE", "identitySquash": "NONE", "anonymousUid": 65534, "anonymousGid": 65534, "isAnonymousAccessAllowed": false, "allowedAuth": ["SYS"] } ]
     *
     * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
     *
     * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
     *
     * **If set to the empty array then the export will not be visible to any clients.**
     *
     * The export's `exportOptions` can be changed after creation using the `UpdateExport` operation.
     */
    public readonly exportOptions!: pulumi.Output<outputs.FileStorage.ExportExportOption[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    public readonly exportSetId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    public readonly fileSystemId!: pulumi.Output<string>;
    /**
     * (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request's RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
     */
    public readonly isIdmapGroupsForSysAuth!: pulumi.Output<boolean>;
    public readonly isLockOverride!: pulumi.Output<boolean>;
    /**
     * Locks associated with this resource.
     */
    public readonly locks!: pulumi.Output<outputs.FileStorage.ExportLock[]>;
    /**
     * Path used to access the associated file system.
     *
     * Avoid entering confidential information.
     *
     * Example: `/mediafiles`
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly path!: pulumi.Output<string>;
    /**
     * The current state of this export.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Export resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExportArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExportArgs | ExportState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExportState | undefined;
            resourceInputs["exportOptions"] = state ? state.exportOptions : undefined;
            resourceInputs["exportSetId"] = state ? state.exportSetId : undefined;
            resourceInputs["fileSystemId"] = state ? state.fileSystemId : undefined;
            resourceInputs["isIdmapGroupsForSysAuth"] = state ? state.isIdmapGroupsForSysAuth : undefined;
            resourceInputs["isLockOverride"] = state ? state.isLockOverride : undefined;
            resourceInputs["locks"] = state ? state.locks : undefined;
            resourceInputs["path"] = state ? state.path : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as ExportArgs | undefined;
            if ((!args || args.exportSetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'exportSetId'");
            }
            if ((!args || args.fileSystemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fileSystemId'");
            }
            if ((!args || args.path === undefined) && !opts.urn) {
                throw new Error("Missing required property 'path'");
            }
            resourceInputs["exportOptions"] = args ? args.exportOptions : undefined;
            resourceInputs["exportSetId"] = args ? args.exportSetId : undefined;
            resourceInputs["fileSystemId"] = args ? args.fileSystemId : undefined;
            resourceInputs["isIdmapGroupsForSysAuth"] = args ? args.isIdmapGroupsForSysAuth : undefined;
            resourceInputs["isLockOverride"] = args ? args.isLockOverride : undefined;
            resourceInputs["locks"] = args ? args.locks : undefined;
            resourceInputs["path"] = args ? args.path : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Export.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Export resources.
 */
export interface ExportState {
    /**
     * (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
     *
     * [ { "source" : "0.0.0.0/0", "requirePrivilegedSourcePort" : false, "access": "READ_WRITE", "identitySquash": "NONE", "anonymousUid": 65534, "anonymousGid": 65534, "isAnonymousAccessAllowed": false, "allowedAuth": ["SYS"] } ]
     *
     * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
     *
     * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
     *
     * **If set to the empty array then the export will not be visible to any clients.**
     *
     * The export's `exportOptions` can be changed after creation using the `UpdateExport` operation.
     */
    exportOptions?: pulumi.Input<pulumi.Input<inputs.FileStorage.ExportExportOption>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    exportSetId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    fileSystemId?: pulumi.Input<string>;
    /**
     * (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request's RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
     */
    isIdmapGroupsForSysAuth?: pulumi.Input<boolean>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.FileStorage.ExportLock>[]>;
    /**
     * Path used to access the associated file system.
     *
     * Avoid entering confidential information.
     *
     * Example: `/mediafiles`
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    path?: pulumi.Input<string>;
    /**
     * The current state of this export.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Export resource.
 */
export interface ExportArgs {
    /**
     * (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
     *
     * [ { "source" : "0.0.0.0/0", "requirePrivilegedSourcePort" : false, "access": "READ_WRITE", "identitySquash": "NONE", "anonymousUid": 65534, "anonymousGid": 65534, "isAnonymousAccessAllowed": false, "allowedAuth": ["SYS"] } ]
     *
     * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
     *
     * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
     *
     * **If set to the empty array then the export will not be visible to any clients.**
     *
     * The export's `exportOptions` can be changed after creation using the `UpdateExport` operation.
     */
    exportOptions?: pulumi.Input<pulumi.Input<inputs.FileStorage.ExportExportOption>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    exportSetId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    fileSystemId: pulumi.Input<string>;
    /**
     * (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request's RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
     */
    isIdmapGroupsForSysAuth?: pulumi.Input<boolean>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.FileStorage.ExportLock>[]>;
    /**
     * Path used to access the associated file system.
     *
     * Avoid entering confidential information.
     *
     * Example: `/mediafiles`
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    path: pulumi.Input<string>;
}
