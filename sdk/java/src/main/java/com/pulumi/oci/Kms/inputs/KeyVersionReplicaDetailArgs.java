// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class KeyVersionReplicaDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final KeyVersionReplicaDetailArgs Empty = new KeyVersionReplicaDetailArgs();

    /**
     * ReplicationId associated with a key version operation
     * 
     */
    @Import(name="replicationId")
    private @Nullable Output<String> replicationId;

    /**
     * @return ReplicationId associated with a key version operation
     * 
     */
    public Optional<Output<String>> replicationId() {
        return Optional.ofNullable(this.replicationId);
    }

    private KeyVersionReplicaDetailArgs() {}

    private KeyVersionReplicaDetailArgs(KeyVersionReplicaDetailArgs $) {
        this.replicationId = $.replicationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(KeyVersionReplicaDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private KeyVersionReplicaDetailArgs $;

        public Builder() {
            $ = new KeyVersionReplicaDetailArgs();
        }

        public Builder(KeyVersionReplicaDetailArgs defaults) {
            $ = new KeyVersionReplicaDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param replicationId ReplicationId associated with a key version operation
         * 
         * @return builder
         * 
         */
        public Builder replicationId(@Nullable Output<String> replicationId) {
            $.replicationId = replicationId;
            return this;
        }

        /**
         * @param replicationId ReplicationId associated with a key version operation
         * 
         * @return builder
         * 
         */
        public Builder replicationId(String replicationId) {
            return replicationId(Output.of(replicationId));
        }

        public KeyVersionReplicaDetailArgs build() {
            return $;
        }
    }

}