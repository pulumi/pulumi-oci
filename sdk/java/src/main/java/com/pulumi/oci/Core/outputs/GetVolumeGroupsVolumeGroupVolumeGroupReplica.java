// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVolumeGroupsVolumeGroupVolumeGroupReplica {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    private String volumeGroupReplicaId;

    private GetVolumeGroupsVolumeGroupVolumeGroupReplica() {}
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The volume group replica&#39;s Oracle ID (OCID).
     * 
     */
    public String volumeGroupReplicaId() {
        return this.volumeGroupReplicaId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeGroupsVolumeGroupVolumeGroupReplica defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String displayName;
        private String volumeGroupReplicaId;
        public Builder() {}
        public Builder(GetVolumeGroupsVolumeGroupVolumeGroupReplica defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.displayName = defaults.displayName;
    	      this.volumeGroupReplicaId = defaults.volumeGroupReplicaId;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetVolumeGroupsVolumeGroupVolumeGroupReplica", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetVolumeGroupsVolumeGroupVolumeGroupReplica", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder volumeGroupReplicaId(String volumeGroupReplicaId) {
            if (volumeGroupReplicaId == null) {
              throw new MissingRequiredPropertyException("GetVolumeGroupsVolumeGroupVolumeGroupReplica", "volumeGroupReplicaId");
            }
            this.volumeGroupReplicaId = volumeGroupReplicaId;
            return this;
        }
        public GetVolumeGroupsVolumeGroupVolumeGroupReplica build() {
            final var _resultValue = new GetVolumeGroupsVolumeGroupVolumeGroupReplica();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.displayName = displayName;
            _resultValue.volumeGroupReplicaId = volumeGroupReplicaId;
            return _resultValue;
        }
    }
}
