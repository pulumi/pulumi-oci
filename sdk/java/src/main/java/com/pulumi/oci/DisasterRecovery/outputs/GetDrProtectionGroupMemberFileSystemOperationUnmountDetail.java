// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupMemberFileSystemOperationUnmountDetail {
    /**
     * @return The OCID of the mount target for this file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
     * 
     */
    private String mountTargetId;

    private GetDrProtectionGroupMemberFileSystemOperationUnmountDetail() {}
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

    public static Builder builder(GetDrProtectionGroupMemberFileSystemOperationUnmountDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String mountTargetId;
        public Builder() {}
        public Builder(GetDrProtectionGroupMemberFileSystemOperationUnmountDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.mountTargetId = defaults.mountTargetId;
        }

        @CustomType.Setter
        public Builder mountTargetId(String mountTargetId) {
            if (mountTargetId == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupMemberFileSystemOperationUnmountDetail", "mountTargetId");
            }
            this.mountTargetId = mountTargetId;
            return this;
        }
        public GetDrProtectionGroupMemberFileSystemOperationUnmountDetail build() {
            final var _resultValue = new GetDrProtectionGroupMemberFileSystemOperationUnmountDetail();
            _resultValue.mountTargetId = mountTargetId;
            return _resultValue;
        }
    }
}
