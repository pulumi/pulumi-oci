// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetKeyReplicaDetail {
    /**
     * @return ReplicationId associated with a key operation
     * 
     */
    private String replicationId;

    private GetKeyReplicaDetail() {}
    /**
     * @return ReplicationId associated with a key operation
     * 
     */
    public String replicationId() {
        return this.replicationId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeyReplicaDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String replicationId;
        public Builder() {}
        public Builder(GetKeyReplicaDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.replicationId = defaults.replicationId;
        }

        @CustomType.Setter
        public Builder replicationId(String replicationId) {
            if (replicationId == null) {
              throw new MissingRequiredPropertyException("GetKeyReplicaDetail", "replicationId");
            }
            this.replicationId = replicationId;
            return this;
        }
        public GetKeyReplicaDetail build() {
            final var _resultValue = new GetKeyReplicaDetail();
            _resultValue.replicationId = replicationId;
            return _resultValue;
        }
    }
}
