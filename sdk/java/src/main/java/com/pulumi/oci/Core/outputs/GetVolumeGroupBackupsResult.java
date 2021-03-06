// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVolumeGroupBackupsFilter;
import com.pulumi.oci.Core.outputs.GetVolumeGroupBackupsVolumeGroupBackup;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVolumeGroupBackupsResult {
    /**
     * @return The OCID of the compartment that contains the volume group backup.
     * 
     */
    private final String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetVolumeGroupBackupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of volume_group_backups.
     * 
     */
    private final List<GetVolumeGroupBackupsVolumeGroupBackup> volumeGroupBackups;
    /**
     * @return The OCID of the source volume group.
     * 
     */
    private final @Nullable String volumeGroupId;

    @CustomType.Constructor
    private GetVolumeGroupBackupsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetVolumeGroupBackupsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("volumeGroupBackups") List<GetVolumeGroupBackupsVolumeGroupBackup> volumeGroupBackups,
        @CustomType.Parameter("volumeGroupId") @Nullable String volumeGroupId) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.volumeGroupBackups = volumeGroupBackups;
        this.volumeGroupId = volumeGroupId;
    }

    /**
     * @return The OCID of the compartment that contains the volume group backup.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetVolumeGroupBackupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of volume_group_backups.
     * 
     */
    public List<GetVolumeGroupBackupsVolumeGroupBackup> volumeGroupBackups() {
        return this.volumeGroupBackups;
    }
    /**
     * @return The OCID of the source volume group.
     * 
     */
    public Optional<String> volumeGroupId() {
        return Optional.ofNullable(this.volumeGroupId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeGroupBackupsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetVolumeGroupBackupsFilter> filters;
        private String id;
        private List<GetVolumeGroupBackupsVolumeGroupBackup> volumeGroupBackups;
        private @Nullable String volumeGroupId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVolumeGroupBackupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.volumeGroupBackups = defaults.volumeGroupBackups;
    	      this.volumeGroupId = defaults.volumeGroupId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetVolumeGroupBackupsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVolumeGroupBackupsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder volumeGroupBackups(List<GetVolumeGroupBackupsVolumeGroupBackup> volumeGroupBackups) {
            this.volumeGroupBackups = Objects.requireNonNull(volumeGroupBackups);
            return this;
        }
        public Builder volumeGroupBackups(GetVolumeGroupBackupsVolumeGroupBackup... volumeGroupBackups) {
            return volumeGroupBackups(List.of(volumeGroupBackups));
        }
        public Builder volumeGroupId(@Nullable String volumeGroupId) {
            this.volumeGroupId = volumeGroupId;
            return this;
        }        public GetVolumeGroupBackupsResult build() {
            return new GetVolumeGroupBackupsResult(compartmentId, displayName, filters, id, volumeGroupBackups, volumeGroupId);
        }
    }
}
