// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VolumeGroupBackupSourceDetails {
    /**
     * @return The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
     * 
     */
    private final @Nullable String kmsKeyId;
    /**
     * @return The region of the volume backup source.
     * 
     */
    private final String region;
    /**
     * @return The OCID of the source volume group backup.
     * 
     */
    private final String volumeGroupBackupId;

    @CustomType.Constructor
    private VolumeGroupBackupSourceDetails(
        @CustomType.Parameter("kmsKeyId") @Nullable String kmsKeyId,
        @CustomType.Parameter("region") String region,
        @CustomType.Parameter("volumeGroupBackupId") String volumeGroupBackupId) {
        this.kmsKeyId = kmsKeyId;
        this.region = region;
        this.volumeGroupBackupId = volumeGroupBackupId;
    }

    /**
     * @return The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
     * 
     */
    public Optional<String> kmsKeyId() {
        return Optional.ofNullable(this.kmsKeyId);
    }
    /**
     * @return The region of the volume backup source.
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return The OCID of the source volume group backup.
     * 
     */
    public String volumeGroupBackupId() {
        return this.volumeGroupBackupId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VolumeGroupBackupSourceDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String kmsKeyId;
        private String region;
        private String volumeGroupBackupId;

        public Builder() {
    	      // Empty
        }

        public Builder(VolumeGroupBackupSourceDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.region = defaults.region;
    	      this.volumeGroupBackupId = defaults.volumeGroupBackupId;
        }

        public Builder kmsKeyId(@Nullable String kmsKeyId) {
            this.kmsKeyId = kmsKeyId;
            return this;
        }
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        public Builder volumeGroupBackupId(String volumeGroupBackupId) {
            this.volumeGroupBackupId = Objects.requireNonNull(volumeGroupBackupId);
            return this;
        }        public VolumeGroupBackupSourceDetails build() {
            return new VolumeGroupBackupSourceDetails(kmsKeyId, region, volumeGroupBackupId);
        }
    }
}
