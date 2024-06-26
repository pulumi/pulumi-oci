// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation {
    /**
     * @return The export path of the file system.  Example: `/fs-export-path`
     * 
     */
    private String exportPath;
    /**
     * @return Mount details of a file system.
     * 
     */
    private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail> mountDetails;
    /**
     * @return The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    private String mountPoint;
    /**
     * @return The OCID of the mount target for this file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    private String mountTargetId;
    /**
     * @return Unmount details for a file system.
     * 
     */
    private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail> unmountDetails;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation() {}
    /**
     * @return The export path of the file system.  Example: `/fs-export-path`
     * 
     */
    public String exportPath() {
        return this.exportPath;
    }
    /**
     * @return Mount details of a file system.
     * 
     */
    public List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail> mountDetails() {
        return this.mountDetails;
    }
    /**
     * @return The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    public String mountPoint() {
        return this.mountPoint;
    }
    /**
     * @return The OCID of the mount target for this file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    public String mountTargetId() {
        return this.mountTargetId;
    }
    /**
     * @return Unmount details for a file system.
     * 
     */
    public List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail> unmountDetails() {
        return this.unmountDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String exportPath;
        private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail> mountDetails;
        private String mountPoint;
        private String mountTargetId;
        private List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail> unmountDetails;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exportPath = defaults.exportPath;
    	      this.mountDetails = defaults.mountDetails;
    	      this.mountPoint = defaults.mountPoint;
    	      this.mountTargetId = defaults.mountTargetId;
    	      this.unmountDetails = defaults.unmountDetails;
        }

        @CustomType.Setter
        public Builder exportPath(String exportPath) {
            if (exportPath == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation", "exportPath");
            }
            this.exportPath = exportPath;
            return this;
        }
        @CustomType.Setter
        public Builder mountDetails(List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail> mountDetails) {
            if (mountDetails == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation", "mountDetails");
            }
            this.mountDetails = mountDetails;
            return this;
        }
        public Builder mountDetails(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationMountDetail... mountDetails) {
            return mountDetails(List.of(mountDetails));
        }
        @CustomType.Setter
        public Builder mountPoint(String mountPoint) {
            if (mountPoint == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation", "mountPoint");
            }
            this.mountPoint = mountPoint;
            return this;
        }
        @CustomType.Setter
        public Builder mountTargetId(String mountTargetId) {
            if (mountTargetId == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation", "mountTargetId");
            }
            this.mountTargetId = mountTargetId;
            return this;
        }
        @CustomType.Setter
        public Builder unmountDetails(List<GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail> unmountDetails) {
            if (unmountDetails == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation", "unmountDetails");
            }
            this.unmountDetails = unmountDetails;
            return this;
        }
        public Builder unmountDetails(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail... unmountDetails) {
            return unmountDetails(List.of(unmountDetails));
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation build() {
            final var _resultValue = new GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperation();
            _resultValue.exportPath = exportPath;
            _resultValue.mountDetails = mountDetails;
            _resultValue.mountPoint = mountPoint;
            _resultValue.mountTargetId = mountTargetId;
            _resultValue.unmountDetails = unmountDetails;
            return _resultValue;
        }
    }
}
