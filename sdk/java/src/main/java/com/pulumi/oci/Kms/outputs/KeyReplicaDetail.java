// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class KeyReplicaDetail {
    /**
     * @return ReplicationId associated with a key operation
     * 
     */
    private final @Nullable String replicationId;

    @CustomType.Constructor
    private KeyReplicaDetail(@CustomType.Parameter("replicationId") @Nullable String replicationId) {
        this.replicationId = replicationId;
    }

    /**
     * @return ReplicationId associated with a key operation
     * 
     */
    public Optional<String> replicationId() {
        return Optional.ofNullable(this.replicationId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(KeyReplicaDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String replicationId;

        public Builder() {
    	      // Empty
        }

        public Builder(KeyReplicaDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.replicationId = defaults.replicationId;
        }

        public Builder replicationId(@Nullable String replicationId) {
            this.replicationId = replicationId;
            return this;
        }        public KeyReplicaDetail build() {
            return new KeyReplicaDetail(replicationId);
        }
    }
}
