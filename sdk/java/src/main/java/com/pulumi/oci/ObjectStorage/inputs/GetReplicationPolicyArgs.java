// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetReplicationPolicyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReplicationPolicyArgs Empty = new GetReplicationPolicyArgs();

    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * The Object Storage namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Object Storage namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * The ID of the replication policy.
     * 
     */
    @Import(name="replicationId", required=true)
    private Output<String> replicationId;

    /**
     * @return The ID of the replication policy.
     * 
     */
    public Output<String> replicationId() {
        return this.replicationId;
    }

    private GetReplicationPolicyArgs() {}

    private GetReplicationPolicyArgs(GetReplicationPolicyArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.replicationId = $.replicationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReplicationPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReplicationPolicyArgs $;

        public Builder() {
            $ = new GetReplicationPolicyArgs();
        }

        public Builder(GetReplicationPolicyArgs defaults) {
            $ = new GetReplicationPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param replicationId The ID of the replication policy.
         * 
         * @return builder
         * 
         */
        public Builder replicationId(Output<String> replicationId) {
            $.replicationId = replicationId;
            return this;
        }

        /**
         * @param replicationId The ID of the replication policy.
         * 
         * @return builder
         * 
         */
        public Builder replicationId(String replicationId) {
            return replicationId(Output.of(replicationId));
        }

        public GetReplicationPolicyArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            $.replicationId = Objects.requireNonNull($.replicationId, "expected parameter 'replicationId' to be non-null");
            return $;
        }
    }

}