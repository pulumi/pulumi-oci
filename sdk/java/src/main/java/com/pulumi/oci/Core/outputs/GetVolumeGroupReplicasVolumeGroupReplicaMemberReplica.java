// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica {
    /**
     * @return The volume replica ID.
     * 
     */
    private final String volumeReplicaId;

    @CustomType.Constructor
    private GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica(@CustomType.Parameter("volumeReplicaId") String volumeReplicaId) {
        this.volumeReplicaId = volumeReplicaId;
    }

    /**
     * @return The volume replica ID.
     * 
     */
    public String volumeReplicaId() {
        return this.volumeReplicaId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String volumeReplicaId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.volumeReplicaId = defaults.volumeReplicaId;
        }

        public Builder volumeReplicaId(String volumeReplicaId) {
            this.volumeReplicaId = Objects.requireNonNull(volumeReplicaId);
            return this;
        }        public GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica build() {
            return new GetVolumeGroupReplicasVolumeGroupReplicaMemberReplica(volumeReplicaId);
        }
    }
}
