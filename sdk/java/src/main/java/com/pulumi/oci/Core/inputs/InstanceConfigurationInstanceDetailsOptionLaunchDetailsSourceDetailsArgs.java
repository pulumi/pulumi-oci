// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsInstanceSourceImageFilterDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs Empty = new InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs();

    /**
     * The OCID of the boot volume used to boot the instance.
     * 
     */
    @Import(name="bootVolumeId")
    private @Nullable Output<String> bootVolumeId;

    /**
     * @return The OCID of the boot volume used to boot the instance.
     * 
     */
    public Optional<Output<String>> bootVolumeId() {
        return Optional.ofNullable(this.bootVolumeId);
    }

    /**
     * The size of the boot volume in GBs. The minimum value is 50 GB and the maximum value is 32,768 GB (32 TB).
     * 
     */
    @Import(name="bootVolumeSizeInGbs")
    private @Nullable Output<String> bootVolumeSizeInGbs;

    /**
     * @return The size of the boot volume in GBs. The minimum value is 50 GB and the maximum value is 32,768 GB (32 TB).
     * 
     */
    public Optional<Output<String>> bootVolumeSizeInGbs() {
        return Optional.ofNullable(this.bootVolumeSizeInGbs);
    }

    /**
     * The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     * Allowed values:
     * 
     */
    @Import(name="bootVolumeVpusPerGb")
    private @Nullable Output<String> bootVolumeVpusPerGb;

    /**
     * @return The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     * 
     * Allowed values:
     * 
     */
    public Optional<Output<String>> bootVolumeVpusPerGb() {
        return Optional.ofNullable(this.bootVolumeVpusPerGb);
    }

    /**
     * The OCID of the image used to boot the instance.
     * 
     */
    @Import(name="imageId")
    private @Nullable Output<String> imageId;

    /**
     * @return The OCID of the image used to boot the instance.
     * 
     */
    public Optional<Output<String>> imageId() {
        return Optional.ofNullable(this.imageId);
    }

    /**
     * These are the criteria for selecting an image. This is required if imageId is not specified.
     * 
     */
    @Import(name="instanceSourceImageFilterDetails")
    private @Nullable Output<InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsInstanceSourceImageFilterDetailsArgs> instanceSourceImageFilterDetails;

    /**
     * @return These are the criteria for selecting an image. This is required if imageId is not specified.
     * 
     */
    public Optional<Output<InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsInstanceSourceImageFilterDetailsArgs>> instanceSourceImageFilterDetails() {
        return Optional.ofNullable(this.instanceSourceImageFilterDetails);
    }

    /**
     * The OCID of the Vault service key to assign as the master encryption key for the volume.
     * 
     */
    @Import(name="kmsKeyId")
    private @Nullable Output<String> kmsKeyId;

    /**
     * @return The OCID of the Vault service key to assign as the master encryption key for the volume.
     * 
     */
    public Optional<Output<String>> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }

    /**
     * The source type for the instance. Use `image` when specifying the image OCID. Use `bootVolume` when specifying the boot volume OCID.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return The source type for the instance. Use `image` when specifying the image OCID. Use `bootVolume` when specifying the boot volume OCID.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs() {}

    private InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs(InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs $) {
        this.bootVolumeId = $.bootVolumeId;
        this.bootVolumeSizeInGbs = $.bootVolumeSizeInGbs;
        this.bootVolumeVpusPerGb = $.bootVolumeVpusPerGb;
        this.imageId = $.imageId;
        this.instanceSourceImageFilterDetails = $.instanceSourceImageFilterDetails;
        this.kmsKeyId = $.kmsKeyId;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs $;

        public Builder() {
            $ = new InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs();
        }

        public Builder(InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs defaults) {
            $ = new InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bootVolumeId The OCID of the boot volume used to boot the instance.
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeId(@Nullable Output<String> bootVolumeId) {
            $.bootVolumeId = bootVolumeId;
            return this;
        }

        /**
         * @param bootVolumeId The OCID of the boot volume used to boot the instance.
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeId(String bootVolumeId) {
            return bootVolumeId(Output.of(bootVolumeId));
        }

        /**
         * @param bootVolumeSizeInGbs The size of the boot volume in GBs. The minimum value is 50 GB and the maximum value is 32,768 GB (32 TB).
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeSizeInGbs(@Nullable Output<String> bootVolumeSizeInGbs) {
            $.bootVolumeSizeInGbs = bootVolumeSizeInGbs;
            return this;
        }

        /**
         * @param bootVolumeSizeInGbs The size of the boot volume in GBs. The minimum value is 50 GB and the maximum value is 32,768 GB (32 TB).
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeSizeInGbs(String bootVolumeSizeInGbs) {
            return bootVolumeSizeInGbs(Output.of(bootVolumeSizeInGbs));
        }

        /**
         * @param bootVolumeVpusPerGb The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * Allowed values:
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeVpusPerGb(@Nullable Output<String> bootVolumeVpusPerGb) {
            $.bootVolumeVpusPerGb = bootVolumeVpusPerGb;
            return this;
        }

        /**
         * @param bootVolumeVpusPerGb The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service&#39;s elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
         * 
         * Allowed values:
         * 
         * @return builder
         * 
         */
        public Builder bootVolumeVpusPerGb(String bootVolumeVpusPerGb) {
            return bootVolumeVpusPerGb(Output.of(bootVolumeVpusPerGb));
        }

        /**
         * @param imageId The OCID of the image used to boot the instance.
         * 
         * @return builder
         * 
         */
        public Builder imageId(@Nullable Output<String> imageId) {
            $.imageId = imageId;
            return this;
        }

        /**
         * @param imageId The OCID of the image used to boot the instance.
         * 
         * @return builder
         * 
         */
        public Builder imageId(String imageId) {
            return imageId(Output.of(imageId));
        }

        /**
         * @param instanceSourceImageFilterDetails These are the criteria for selecting an image. This is required if imageId is not specified.
         * 
         * @return builder
         * 
         */
        public Builder instanceSourceImageFilterDetails(@Nullable Output<InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsInstanceSourceImageFilterDetailsArgs> instanceSourceImageFilterDetails) {
            $.instanceSourceImageFilterDetails = instanceSourceImageFilterDetails;
            return this;
        }

        /**
         * @param instanceSourceImageFilterDetails These are the criteria for selecting an image. This is required if imageId is not specified.
         * 
         * @return builder
         * 
         */
        public Builder instanceSourceImageFilterDetails(InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsInstanceSourceImageFilterDetailsArgs instanceSourceImageFilterDetails) {
            return instanceSourceImageFilterDetails(Output.of(instanceSourceImageFilterDetails));
        }

        /**
         * @param kmsKeyId The OCID of the Vault service key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(@Nullable Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId The OCID of the Vault service key to assign as the master encryption key for the volume.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        /**
         * @param sourceType The source type for the instance. Use `image` when specifying the image OCID. Use `bootVolume` when specifying the boot volume OCID.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType The source type for the instance. Use `image` when specifying the image OCID. Use `bootVolume` when specifying the boot volume OCID.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public InstanceConfigurationInstanceDetailsOptionLaunchDetailsSourceDetailsArgs build() {
            $.sourceType = Objects.requireNonNull($.sourceType, "expected parameter 'sourceType' to be non-null");
            return $;
        }
    }

}