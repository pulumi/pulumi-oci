// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs Empty = new DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs();

    /**
     * (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    @Import(name="mountPoint")
    private @Nullable Output<String> mountPoint;

    /**
     * @return (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
     * 
     */
    public Optional<Output<String>> mountPoint() {
        return Optional.ofNullable(this.mountPoint);
    }

    private DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs() {}

    private DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs(DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs $) {
        this.mountPoint = $.mountPoint;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs $;

        public Builder() {
            $ = new DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs();
        }

        public Builder(DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs defaults) {
            $ = new DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param mountPoint (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
         * 
         * @return builder
         * 
         */
        public Builder mountPoint(@Nullable Output<String> mountPoint) {
            $.mountPoint = mountPoint;
            return this;
        }

        /**
         * @param mountPoint (Updatable) The physical mount point of the file system on a host.  Example: `/mnt/yourmountpoint`
         * 
         * @return builder
         * 
         */
        public Builder mountPoint(String mountPoint) {
            return mountPoint(Output.of(mountPoint));
        }

        public DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs build() {
            return $;
        }
    }

}