// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetReplicationStatusReplicaDetail {
    /**
     * @return The replica region
     * 
     */
    private String region;
    /**
     * @return Replication status associated with a replicationId
     * 
     */
    private String status;

    private GetReplicationStatusReplicaDetail() {}
    /**
     * @return The replica region
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return Replication status associated with a replicationId
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicationStatusReplicaDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String region;
        private String status;
        public Builder() {}
        public Builder(GetReplicationStatusReplicaDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.region = defaults.region;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetReplicationStatusReplicaDetail build() {
            final var o = new GetReplicationStatusReplicaDetail();
            o.region = region;
            o.status = status;
            return o;
        }
    }
}