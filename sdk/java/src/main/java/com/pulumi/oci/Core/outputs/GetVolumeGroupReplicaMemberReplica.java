// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVolumeGroupReplicaMemberReplica {
    /**
     * @return Membership state of the volume replica in relation to the volume group replica.
     * 
     */
    private String membershipState;
    /**
     * @return The volume replica ID.
     * 
     */
    private String volumeReplicaId;

    private GetVolumeGroupReplicaMemberReplica() {}
    /**
     * @return Membership state of the volume replica in relation to the volume group replica.
     * 
     */
    public String membershipState() {
        return this.membershipState;
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

    public static Builder builder(GetVolumeGroupReplicaMemberReplica defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String membershipState;
        private String volumeReplicaId;
        public Builder() {}
        public Builder(GetVolumeGroupReplicaMemberReplica defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.membershipState = defaults.membershipState;
    	      this.volumeReplicaId = defaults.volumeReplicaId;
        }

        @CustomType.Setter
        public Builder membershipState(String membershipState) {
            this.membershipState = Objects.requireNonNull(membershipState);
            return this;
        }
        @CustomType.Setter
        public Builder volumeReplicaId(String volumeReplicaId) {
            this.volumeReplicaId = Objects.requireNonNull(volumeReplicaId);
            return this;
        }
        public GetVolumeGroupReplicaMemberReplica build() {
            final var o = new GetVolumeGroupReplicaMemberReplica();
            o.membershipState = membershipState;
            o.volumeReplicaId = volumeReplicaId;
            return o;
        }
    }
}