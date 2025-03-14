// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail {
    /**
     * @return The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    private String mountPoint;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail() {}
    /**
     * @return The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    public String mountPoint() {
        return this.mountPoint;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String mountPoint;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.mountPoint = defaults.mountPoint;
        }

        @CustomType.Setter
        public Builder mountPoint(String mountPoint) {
            if (mountPoint == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail", "mountPoint");
            }
            this.mountPoint = mountPoint;
            return this;
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail build() {
            final var _resultValue = new GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberBlockVolumeOperationMountDetail();
            _resultValue.mountPoint = mountPoint;
            return _resultValue;
        }
    }
}
