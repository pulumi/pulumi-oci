// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVolumeGroupsVolumeGroupSourceDetail {
    /**
     * @return The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeIds`
     * 
     */
    private final String type;
    /**
     * @return The OCID of the volume group backup to restore from, if the type is `volumeGroupBackup`
     * 
     */
    private final String volumeGroupBackupId;
    /**
     * @return The OCID of the volume group to clone from, if the type is `volumeGroup`
     * 
     */
    private final String volumeGroupId;
    /**
     * @return The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    private final String volumeGroupReplicaId;
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    private final List<String> volumeIds;

    @CustomType.Constructor
    private GetVolumeGroupsVolumeGroupSourceDetail(
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("volumeGroupBackupId") String volumeGroupBackupId,
        @CustomType.Parameter("volumeGroupId") String volumeGroupId,
        @CustomType.Parameter("volumeGroupReplicaId") String volumeGroupReplicaId,
        @CustomType.Parameter("volumeIds") List<String> volumeIds) {
        this.type = type;
        this.volumeGroupBackupId = volumeGroupBackupId;
        this.volumeGroupId = volumeGroupId;
        this.volumeGroupReplicaId = volumeGroupReplicaId;
        this.volumeIds = volumeIds;
    }

    /**
     * @return The type can be one of these values: `volumeGroupBackupId`, `volumeGroupId`, `volumeIds`
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The OCID of the volume group backup to restore from, if the type is `volumeGroupBackup`
     * 
     */
    public String volumeGroupBackupId() {
        return this.volumeGroupBackupId;
    }
    /**
     * @return The OCID of the volume group to clone from, if the type is `volumeGroup`
     * 
     */
    public String volumeGroupId() {
        return this.volumeGroupId;
    }
    /**
     * @return The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    public String volumeGroupReplicaId() {
        return this.volumeGroupReplicaId;
    }
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    public List<String> volumeIds() {
        return this.volumeIds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeGroupsVolumeGroupSourceDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String type;
        private String volumeGroupBackupId;
        private String volumeGroupId;
        private String volumeGroupReplicaId;
        private List<String> volumeIds;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVolumeGroupsVolumeGroupSourceDetail defaults) {
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
        public Builder volumeGroupBackupId(String volumeGroupBackupId) {
            this.volumeGroupBackupId = Objects.requireNonNull(volumeGroupBackupId);
            return this;
        }
        public Builder volumeGroupId(String volumeGroupId) {
            this.volumeGroupId = Objects.requireNonNull(volumeGroupId);
            return this;
        }
        public Builder volumeGroupReplicaId(String volumeGroupReplicaId) {
            this.volumeGroupReplicaId = Objects.requireNonNull(volumeGroupReplicaId);
            return this;
        }
        public Builder volumeIds(List<String> volumeIds) {
            this.volumeIds = Objects.requireNonNull(volumeIds);
            return this;
        }
        public Builder volumeIds(String... volumeIds) {
            return volumeIds(List.of(volumeIds));
        }        public GetVolumeGroupsVolumeGroupSourceDetail build() {
            return new GetVolumeGroupsVolumeGroupSourceDetail(type, volumeGroupBackupId, volumeGroupId, volumeGroupReplicaId, volumeIds);
        }
    }
}
