// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.DrProtectionGroupMemberFileSystemOperationMountDetails;
import com.pulumi.oci.DisasterRecovery.outputs.DrProtectionGroupMemberFileSystemOperationUnmountDetails;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrProtectionGroupMemberFileSystemOperation {
    /**
     * @return (Updatable) The export path of the file system.  Example: `/fs-export-path`
     * 
     */
    private @Nullable String exportPath;
    /**
     * @return (Updatable) The details for creating a file system mount.
     * 
     */
    private @Nullable DrProtectionGroupMemberFileSystemOperationMountDetails mountDetails;
    /**
     * @return (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    private @Nullable String mountPoint;
    /**
     * @return (Updatable) The OCID of the mount target.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    private @Nullable String mountTargetId;
    /**
     * @return (Updatable) The details for creating a file system unmount.
     * 
     */
    private @Nullable DrProtectionGroupMemberFileSystemOperationUnmountDetails unmountDetails;

    private DrProtectionGroupMemberFileSystemOperation() {}
    /**
     * @return (Updatable) The export path of the file system.  Example: `/fs-export-path`
     * 
     */
    public Optional<String> exportPath() {
        return Optional.ofNullable(this.exportPath);
    }
    /**
     * @return (Updatable) The details for creating a file system mount.
     * 
     */
    public Optional<DrProtectionGroupMemberFileSystemOperationMountDetails> mountDetails() {
        return Optional.ofNullable(this.mountDetails);
    }
    /**
     * @return (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    public Optional<String> mountPoint() {
        return Optional.ofNullable(this.mountPoint);
    }
    /**
     * @return (Updatable) The OCID of the mount target.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    public Optional<String> mountTargetId() {
        return Optional.ofNullable(this.mountTargetId);
    }
    /**
     * @return (Updatable) The details for creating a file system unmount.
     * 
     */
    public Optional<DrProtectionGroupMemberFileSystemOperationUnmountDetails> unmountDetails() {
        return Optional.ofNullable(this.unmountDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrProtectionGroupMemberFileSystemOperation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String exportPath;
        private @Nullable DrProtectionGroupMemberFileSystemOperationMountDetails mountDetails;
        private @Nullable String mountPoint;
        private @Nullable String mountTargetId;
        private @Nullable DrProtectionGroupMemberFileSystemOperationUnmountDetails unmountDetails;
        public Builder() {}
        public Builder(DrProtectionGroupMemberFileSystemOperation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exportPath = defaults.exportPath;
    	      this.mountDetails = defaults.mountDetails;
    	      this.mountPoint = defaults.mountPoint;
    	      this.mountTargetId = defaults.mountTargetId;
    	      this.unmountDetails = defaults.unmountDetails;
        }

        @CustomType.Setter
        public Builder exportPath(@Nullable String exportPath) {
            this.exportPath = exportPath;
            return this;
        }
        @CustomType.Setter
        public Builder mountDetails(@Nullable DrProtectionGroupMemberFileSystemOperationMountDetails mountDetails) {
            this.mountDetails = mountDetails;
            return this;
        }
        @CustomType.Setter
        public Builder mountPoint(@Nullable String mountPoint) {
            this.mountPoint = mountPoint;
            return this;
        }
        @CustomType.Setter
        public Builder mountTargetId(@Nullable String mountTargetId) {
            this.mountTargetId = mountTargetId;
            return this;
        }
        @CustomType.Setter
        public Builder unmountDetails(@Nullable DrProtectionGroupMemberFileSystemOperationUnmountDetails unmountDetails) {
            this.unmountDetails = unmountDetails;
            return this;
        }
        public DrProtectionGroupMemberFileSystemOperation build() {
            final var o = new DrProtectionGroupMemberFileSystemOperation();
            o.exportPath = exportPath;
            o.mountDetails = mountDetails;
            o.mountPoint = mountPoint;
            o.mountTargetId = mountTargetId;
            o.unmountDetails = unmountDetails;
            return o;
        }
    }
}