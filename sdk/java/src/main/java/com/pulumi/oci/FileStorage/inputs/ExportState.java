// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FileStorage.inputs.ExportExportOptionArgs;
import com.pulumi.oci.FileStorage.inputs.ExportLockArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExportState extends com.pulumi.resources.ResourceArgs {

    public static final ExportState Empty = new ExportState();

    /**
     * (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
     * 
     * [ { &#34;source&#34; : &#34;0.0.0.0/0&#34;, &#34;requirePrivilegedSourcePort&#34; : false, &#34;access&#34;: &#34;READ_WRITE&#34;, &#34;identitySquash&#34;: &#34;NONE&#34;, &#34;anonymousUid&#34;: 65534, &#34;anonymousGid&#34;: 65534, &#34;isAnonymousAccessAllowed&#34;: false, &#34;allowedAuth&#34;: [&#34;SYS&#34;] } ]
     * 
     * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
     * 
     * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
     * 
     * **If set to the empty array then the export will not be visible to any clients.**
     * 
     * The export&#39;s `exportOptions` can be changed after creation using the `UpdateExport` operation.
     * 
     */
    @Import(name="exportOptions")
    private @Nullable Output<List<ExportExportOptionArgs>> exportOptions;

    /**
     * @return (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
     * 
     * [ { &#34;source&#34; : &#34;0.0.0.0/0&#34;, &#34;requirePrivilegedSourcePort&#34; : false, &#34;access&#34;: &#34;READ_WRITE&#34;, &#34;identitySquash&#34;: &#34;NONE&#34;, &#34;anonymousUid&#34;: 65534, &#34;anonymousGid&#34;: 65534, &#34;isAnonymousAccessAllowed&#34;: false, &#34;allowedAuth&#34;: [&#34;SYS&#34;] } ]
     * 
     * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
     * 
     * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
     * 
     * **If set to the empty array then the export will not be visible to any clients.**
     * 
     * The export&#39;s `exportOptions` can be changed after creation using the `UpdateExport` operation.
     * 
     */
    public Optional<Output<List<ExportExportOptionArgs>>> exportOptions() {
        return Optional.ofNullable(this.exportOptions);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    @Import(name="exportSetId")
    private @Nullable Output<String> exportSetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    public Optional<Output<String>> exportSetId() {
        return Optional.ofNullable(this.exportSetId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    @Import(name="fileSystemId")
    private @Nullable Output<String> fileSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    public Optional<Output<String>> fileSystemId() {
        return Optional.ofNullable(this.fileSystemId);
    }

    /**
     * (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request&#39;s RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
     * 
     */
    @Import(name="isIdmapGroupsForSysAuth")
    private @Nullable Output<Boolean> isIdmapGroupsForSysAuth;

    /**
     * @return (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request&#39;s RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
     * 
     */
    public Optional<Output<Boolean>> isIdmapGroupsForSysAuth() {
        return Optional.ofNullable(this.isIdmapGroupsForSysAuth);
    }

    @Import(name="isLockOverride")
    private @Nullable Output<Boolean> isLockOverride;

    public Optional<Output<Boolean>> isLockOverride() {
        return Optional.ofNullable(this.isLockOverride);
    }

    /**
     * Locks associated with this resource.
     * 
     */
    @Import(name="locks")
    private @Nullable Output<List<ExportLockArgs>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Optional<Output<List<ExportLockArgs>>> locks() {
        return Optional.ofNullable(this.locks);
    }

    /**
     * Path used to access the associated file system.
     * 
     * Avoid entering confidential information.
     * 
     * Example: `/mediafiles`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="path")
    private @Nullable Output<String> path;

    /**
     * @return Path used to access the associated file system.
     * 
     * Avoid entering confidential information.
     * 
     * Example: `/mediafiles`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> path() {
        return Optional.ofNullable(this.path);
    }

    /**
     * The current state of this export.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of this export.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private ExportState() {}

    private ExportState(ExportState $) {
        this.exportOptions = $.exportOptions;
        this.exportSetId = $.exportSetId;
        this.fileSystemId = $.fileSystemId;
        this.isIdmapGroupsForSysAuth = $.isIdmapGroupsForSysAuth;
        this.isLockOverride = $.isLockOverride;
        this.locks = $.locks;
        this.path = $.path;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExportState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExportState $;

        public Builder() {
            $ = new ExportState();
        }

        public Builder(ExportState defaults) {
            $ = new ExportState(Objects.requireNonNull(defaults));
        }

        /**
         * @param exportOptions (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
         * 
         * [ { &#34;source&#34; : &#34;0.0.0.0/0&#34;, &#34;requirePrivilegedSourcePort&#34; : false, &#34;access&#34;: &#34;READ_WRITE&#34;, &#34;identitySquash&#34;: &#34;NONE&#34;, &#34;anonymousUid&#34;: 65534, &#34;anonymousGid&#34;: 65534, &#34;isAnonymousAccessAllowed&#34;: false, &#34;allowedAuth&#34;: [&#34;SYS&#34;] } ]
         * 
         * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
         * 
         * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
         * 
         * **If set to the empty array then the export will not be visible to any clients.**
         * 
         * The export&#39;s `exportOptions` can be changed after creation using the `UpdateExport` operation.
         * 
         * @return builder
         * 
         */
        public Builder exportOptions(@Nullable Output<List<ExportExportOptionArgs>> exportOptions) {
            $.exportOptions = exportOptions;
            return this;
        }

        /**
         * @param exportOptions (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
         * 
         * [ { &#34;source&#34; : &#34;0.0.0.0/0&#34;, &#34;requirePrivilegedSourcePort&#34; : false, &#34;access&#34;: &#34;READ_WRITE&#34;, &#34;identitySquash&#34;: &#34;NONE&#34;, &#34;anonymousUid&#34;: 65534, &#34;anonymousGid&#34;: 65534, &#34;isAnonymousAccessAllowed&#34;: false, &#34;allowedAuth&#34;: [&#34;SYS&#34;] } ]
         * 
         * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
         * 
         * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
         * 
         * **If set to the empty array then the export will not be visible to any clients.**
         * 
         * The export&#39;s `exportOptions` can be changed after creation using the `UpdateExport` operation.
         * 
         * @return builder
         * 
         */
        public Builder exportOptions(List<ExportExportOptionArgs> exportOptions) {
            return exportOptions(Output.of(exportOptions));
        }

        /**
         * @param exportOptions (Updatable) Export options for the new export. For exports of mount targets with IPv4 address, if client options are left unspecified, client options would default to:
         * 
         * [ { &#34;source&#34; : &#34;0.0.0.0/0&#34;, &#34;requirePrivilegedSourcePort&#34; : false, &#34;access&#34;: &#34;READ_WRITE&#34;, &#34;identitySquash&#34;: &#34;NONE&#34;, &#34;anonymousUid&#34;: 65534, &#34;anonymousGid&#34;: 65534, &#34;isAnonymousAccessAllowed&#34;: false, &#34;allowedAuth&#34;: [&#34;SYS&#34;] } ]
         * 
         * For exports of mount targets with IPv6 address, if client options are left unspecified, client options would be an empty array, i.e. export would not be visible to any clients.
         * 
         * **Note:** Mount targets do not have Internet-routable IP addresses.  Therefore they will not be reachable from the Internet, even if an associated `ClientOptions` item has a source of `0.0.0.0/0`.
         * 
         * **If set to the empty array then the export will not be visible to any clients.**
         * 
         * The export&#39;s `exportOptions` can be changed after creation using the `UpdateExport` operation.
         * 
         * @return builder
         * 
         */
        public Builder exportOptions(ExportExportOptionArgs... exportOptions) {
            return exportOptions(List.of(exportOptions));
        }

        /**
         * @param exportSetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
         * 
         * @return builder
         * 
         */
        public Builder exportSetId(@Nullable Output<String> exportSetId) {
            $.exportSetId = exportSetId;
            return this;
        }

        /**
         * @param exportSetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
         * 
         * @return builder
         * 
         */
        public Builder exportSetId(String exportSetId) {
            return exportSetId(Output.of(exportSetId));
        }

        /**
         * @param fileSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemId(@Nullable Output<String> fileSystemId) {
            $.fileSystemId = fileSystemId;
            return this;
        }

        /**
         * @param fileSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
         * 
         * @return builder
         * 
         */
        public Builder fileSystemId(String fileSystemId) {
            return fileSystemId(Output.of(fileSystemId));
        }

        /**
         * @param isIdmapGroupsForSysAuth (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request&#39;s RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
         * 
         * @return builder
         * 
         */
        public Builder isIdmapGroupsForSysAuth(@Nullable Output<Boolean> isIdmapGroupsForSysAuth) {
            $.isIdmapGroupsForSysAuth = isIdmapGroupsForSysAuth;
            return this;
        }

        /**
         * @param isIdmapGroupsForSysAuth (Updatable) Whether or not the export should use ID mapping for Unix groups rather than the group list provided within an NFS request&#39;s RPC header. When this flag is true the Unix UID from the RPC header is used to retrieve the list of secondary groups from a the ID mapping subsystem. The primary GID is always taken from the RPC header. If ID mapping is not configured, incorrectly configured, unavailable, or cannot be used to determine a list of secondary groups then an empty secondary group list is used for authorization. If the number of groups exceeds the limit of 256 groups, the list retrieved from LDAP is truncated to the first 256 groups read.
         * 
         * @return builder
         * 
         */
        public Builder isIdmapGroupsForSysAuth(Boolean isIdmapGroupsForSysAuth) {
            return isIdmapGroupsForSysAuth(Output.of(isIdmapGroupsForSysAuth));
        }

        public Builder isLockOverride(@Nullable Output<Boolean> isLockOverride) {
            $.isLockOverride = isLockOverride;
            return this;
        }

        public Builder isLockOverride(Boolean isLockOverride) {
            return isLockOverride(Output.of(isLockOverride));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(@Nullable Output<List<ExportLockArgs>> locks) {
            $.locks = locks;
            return this;
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(List<ExportLockArgs> locks) {
            return locks(Output.of(locks));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(ExportLockArgs... locks) {
            return locks(List.of(locks));
        }

        /**
         * @param path Path used to access the associated file system.
         * 
         * Avoid entering confidential information.
         * 
         * Example: `/mediafiles`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder path(@Nullable Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path Path used to access the associated file system.
         * 
         * Avoid entering confidential information.
         * 
         * Example: `/mediafiles`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param state The current state of this export.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of this export.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public ExportState build() {
            return $;
        }
    }

}
