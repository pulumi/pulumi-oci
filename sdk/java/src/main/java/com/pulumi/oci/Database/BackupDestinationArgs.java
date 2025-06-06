// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.BackupDestinationMountTypeDetailsArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackupDestinationArgs extends com.pulumi.resources.ResourceArgs {

    public static final BackupDestinationArgs Empty = new BackupDestinationArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The connection string for connecting to the Recovery Appliance.
     * 
     */
    @Import(name="connectionString")
    private @Nullable Output<String> connectionString;

    /**
     * @return (Updatable) The connection string for connecting to the Recovery Appliance.
     * 
     */
    public Optional<Output<String>> connectionString() {
        return Optional.ofNullable(this.connectionString);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The user-provided name of the backup destination.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return The user-provided name of the backup destination.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) **Deprecated.** The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes. This field is deprecated. Use the mountTypeDetails field instead to specify the mount type for NFS.
     * 
     * @deprecated
     * The &#39;local_mount_point_path&#39; field has been deprecated. Please use &#39;local_mount_point_path under mount_type_details&#39; instead.
     * 
     */
    @Deprecated /* The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead. */
    @Import(name="localMountPointPath")
    private @Nullable Output<String> localMountPointPath;

    /**
     * @return (Updatable) **Deprecated.** The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes. This field is deprecated. Use the mountTypeDetails field instead to specify the mount type for NFS.
     * 
     * @deprecated
     * The &#39;local_mount_point_path&#39; field has been deprecated. Please use &#39;local_mount_point_path under mount_type_details&#39; instead.
     * 
     */
    @Deprecated /* The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead. */
    public Optional<Output<String>> localMountPointPath() {
        return Optional.ofNullable(this.localMountPointPath);
    }

    /**
     * Mount type details for backup destination.
     * 
     */
    @Import(name="mountTypeDetails")
    private @Nullable Output<BackupDestinationMountTypeDetailsArgs> mountTypeDetails;

    /**
     * @return Mount type details for backup destination.
     * 
     */
    public Optional<Output<BackupDestinationMountTypeDetailsArgs>> mountTypeDetails() {
        return Optional.ofNullable(this.mountTypeDetails);
    }

    /**
     * Type of the backup destination.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return Type of the backup destination.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) The Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vpcUsers")
    private @Nullable Output<List<String>> vpcUsers;

    /**
     * @return (Updatable) The Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<List<String>>> vpcUsers() {
        return Optional.ofNullable(this.vpcUsers);
    }

    private BackupDestinationArgs() {}

    private BackupDestinationArgs(BackupDestinationArgs $) {
        this.compartmentId = $.compartmentId;
        this.connectionString = $.connectionString;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.localMountPointPath = $.localMountPointPath;
        this.mountTypeDetails = $.mountTypeDetails;
        this.type = $.type;
        this.vpcUsers = $.vpcUsers;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackupDestinationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackupDestinationArgs $;

        public Builder() {
            $ = new BackupDestinationArgs();
        }

        public Builder(BackupDestinationArgs defaults) {
            $ = new BackupDestinationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param connectionString (Updatable) The connection string for connecting to the Recovery Appliance.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(@Nullable Output<String> connectionString) {
            $.connectionString = connectionString;
            return this;
        }

        /**
         * @param connectionString (Updatable) The connection string for connecting to the Recovery Appliance.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(String connectionString) {
            return connectionString(Output.of(connectionString));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName The user-provided name of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-provided name of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param localMountPointPath (Updatable) **Deprecated.** The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes. This field is deprecated. Use the mountTypeDetails field instead to specify the mount type for NFS.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;local_mount_point_path&#39; field has been deprecated. Please use &#39;local_mount_point_path under mount_type_details&#39; instead.
         * 
         */
        @Deprecated /* The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead. */
        public Builder localMountPointPath(@Nullable Output<String> localMountPointPath) {
            $.localMountPointPath = localMountPointPath;
            return this;
        }

        /**
         * @param localMountPointPath (Updatable) **Deprecated.** The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes. This field is deprecated. Use the mountTypeDetails field instead to specify the mount type for NFS.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;local_mount_point_path&#39; field has been deprecated. Please use &#39;local_mount_point_path under mount_type_details&#39; instead.
         * 
         */
        @Deprecated /* The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead. */
        public Builder localMountPointPath(String localMountPointPath) {
            return localMountPointPath(Output.of(localMountPointPath));
        }

        /**
         * @param mountTypeDetails Mount type details for backup destination.
         * 
         * @return builder
         * 
         */
        public Builder mountTypeDetails(@Nullable Output<BackupDestinationMountTypeDetailsArgs> mountTypeDetails) {
            $.mountTypeDetails = mountTypeDetails;
            return this;
        }

        /**
         * @param mountTypeDetails Mount type details for backup destination.
         * 
         * @return builder
         * 
         */
        public Builder mountTypeDetails(BackupDestinationMountTypeDetailsArgs mountTypeDetails) {
            return mountTypeDetails(Output.of(mountTypeDetails));
        }

        /**
         * @param type Type of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param vpcUsers (Updatable) The Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vpcUsers(@Nullable Output<List<String>> vpcUsers) {
            $.vpcUsers = vpcUsers;
            return this;
        }

        /**
         * @param vpcUsers (Updatable) The Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vpcUsers(List<String> vpcUsers) {
            return vpcUsers(Output.of(vpcUsers));
        }

        /**
         * @param vpcUsers (Updatable) The Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vpcUsers(String... vpcUsers) {
            return vpcUsers(List.of(vpcUsers));
        }

        public BackupDestinationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("BackupDestinationArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("BackupDestinationArgs", "displayName");
            }
            if ($.type == null) {
                throw new MissingRequiredPropertyException("BackupDestinationArgs", "type");
            }
            return $;
        }
    }

}
