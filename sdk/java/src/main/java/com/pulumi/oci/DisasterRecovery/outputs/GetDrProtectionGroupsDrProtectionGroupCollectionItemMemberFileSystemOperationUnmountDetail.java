// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail {
    /**
     * @return The OCID of the mount target for this file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    private String mountTargetId;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail() {}
    /**
     * @return The OCID of the mount target for this file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    public String mountTargetId() {
        return this.mountTargetId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String mountTargetId;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.mountTargetId = defaults.mountTargetId;
        }

        @CustomType.Setter
        public Builder mountTargetId(String mountTargetId) {
            this.mountTargetId = Objects.requireNonNull(mountTargetId);
            return this;
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail build() {
            final var o = new GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberFileSystemOperationUnmountDetail();
            o.mountTargetId = mountTargetId;
            return o;
        }
    }
}