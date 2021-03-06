// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VolumeGroupSourceDetails {
    /**
     * @return The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
     * 
     */
    private final String type;
    /**
     * @return The OCID of the volume group backup to restore from.
     * 
     */
    private final @Nullable String volumeGroupBackupId;
    /**
     * @return The OCID of the volume group to clone from.
     * 
     */
    private final @Nullable String volumeGroupId;
    /**
     * @return The OCID of the volume group replica.
     * 
     */
    private final @Nullable String volumeGroupReplicaId;
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    private final @Nullable List<String> volumeIds;

    @CustomType.Constructor
    private VolumeGroupSourceDetails(
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("volumeGroupBackupId") @Nullable String volumeGroupBackupId,
        @CustomType.Parameter("volumeGroupId") @Nullable String volumeGroupId,
        @CustomType.Parameter("volumeGroupReplicaId") @Nullable String volumeGroupReplicaId,
        @CustomType.Parameter("volumeIds") @Nullable List<String> volumeIds) {
        this.type = type;
        this.volumeGroupBackupId = volumeGroupBackupId;
        this.volumeGroupId = volumeGroupId;
        this.volumeGroupReplicaId = volumeGroupReplicaId;
        this.volumeIds = volumeIds;
    }

    /**
     * @return The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeGroupReplicaId`, `volumeIds`
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The OCID of the volume group backup to restore from.
     * 
     */
    public Optional<String> volumeGroupBackupId() {
        return Optional.ofNullable(this.volumeGroupBackupId);
    }
    /**
     * @return The OCID of the volume group to clone from.
     * 
     */
    public Optional<String> volumeGroupId() {
        return Optional.ofNullable(this.volumeGroupId);
    }
    /**
     * @return The OCID of the volume group replica.
     * 
     */
    public Optional<String> volumeGroupReplicaId() {
        return Optional.ofNullable(this.volumeGroupReplicaId);
    }
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    public List<String> volumeIds() {
        return this.volumeIds == null ? List.of() : this.volumeIds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VolumeGroupSourceDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String type;
        private @Nullable String volumeGroupBackupId;
        private @Nullable String volumeGroupId;
        private @Nullable String volumeGroupReplicaId;
        private @Nullable List<String> volumeIds;

        public Builder() {
    	      // Empty
        }

        public Builder(VolumeGroupSourceDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.volumeGroupBackupId = defaults.volumeGroupBackupId;
    	      this.volumeGroupId = defaults.volumeGroupId;
    	      this.volumeGroupReplicaId = defaults.volumeGroupReplicaId;
    	      this.volumeIds = defaults.volumeIds;
        }

        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder volumeGroupBackupId(@Nullable String volumeGroupBackupId) {
            this.volumeGroupBackupId = volumeGroupBackupId;
            return this;
        }
        public Builder volumeGroupId(@Nullable String volumeGroupId) {
            this.volumeGroupId = volumeGroupId;
            return this;
        }
        public Builder volumeGroupReplicaId(@Nullable String volumeGroupReplicaId) {
            this.volumeGroupReplicaId = volumeGroupReplicaId;
            return this;
        }
        public Builder volumeIds(@Nullable List<String> volumeIds) {
            this.volumeIds = volumeIds;
            return this;
        }
        public Builder volumeIds(String... volumeIds) {
            return volumeIds(List.of(volumeIds));
        }        public VolumeGroupSourceDetails build() {
            return new VolumeGroupSourceDetails(type, volumeGroupBackupId, volumeGroupId, volumeGroupReplicaId, volumeIds);
        }
    }
}
