// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetReplicationPolicyResult {
    private final String bucket;
    /**
     * @deprecated
     * The &#39;delete_object_in_destination_bucket&#39; field has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'delete_object_in_destination_bucket' field has been deprecated. It is no longer supported. */
    private final String deleteObjectInDestinationBucket;
    /**
     * @return The bucket to replicate to in the destination region. Replication policy creation does not automatically create a destination bucket. Create the destination bucket before creating the policy.
     * 
     */
    private final String destinationBucketName;
    /**
     * @return The destination region to replicate to, for example &#34;us-ashburn-1&#34;.
     * 
     */
    private final String destinationRegionName;
    /**
     * @return The id of the replication policy.
     * 
     */
    private final String id;
    /**
     * @return The name of the policy.
     * 
     */
    private final String name;
    private final String namespace;
    private final String replicationId;
    /**
     * @return The replication status of the policy. If the status is CLIENT_ERROR, once the user fixes the issue described in the status message, the status will become ACTIVE.
     * 
     */
    private final String status;
    /**
     * @return A human-readable description of the status.
     * 
     */
    private final String statusMessage;
    /**
     * @return The date when the replication policy was created as per [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeCreated;
    /**
     * @return Changes made to the source bucket before this time has been replicated.
     * 
     */
    private final String timeLastSync;

    @CustomType.Constructor
    private GetReplicationPolicyResult(
        @CustomType.Parameter("bucket") String bucket,
        @CustomType.Parameter("deleteObjectInDestinationBucket") String deleteObjectInDestinationBucket,
        @CustomType.Parameter("destinationBucketName") String destinationBucketName,
        @CustomType.Parameter("destinationRegionName") String destinationRegionName,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("namespace") String namespace,
        @CustomType.Parameter("replicationId") String replicationId,
        @CustomType.Parameter("status") String status,
        @CustomType.Parameter("statusMessage") String statusMessage,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeLastSync") String timeLastSync) {
        this.bucket = bucket;
        this.deleteObjectInDestinationBucket = deleteObjectInDestinationBucket;
        this.destinationBucketName = destinationBucketName;
        this.destinationRegionName = destinationRegionName;
        this.id = id;
        this.name = name;
        this.namespace = namespace;
        this.replicationId = replicationId;
        this.status = status;
        this.statusMessage = statusMessage;
        this.timeCreated = timeCreated;
        this.timeLastSync = timeLastSync;
    }

    public String bucket() {
        return this.bucket;
    }
    /**
     * @deprecated
     * The &#39;delete_object_in_destination_bucket&#39; field has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'delete_object_in_destination_bucket' field has been deprecated. It is no longer supported. */
    public String deleteObjectInDestinationBucket() {
        return this.deleteObjectInDestinationBucket;
    }
    /**
     * @return The bucket to replicate to in the destination region. Replication policy creation does not automatically create a destination bucket. Create the destination bucket before creating the policy.
     * 
     */
    public String destinationBucketName() {
        return this.destinationBucketName;
    }
    /**
     * @return The destination region to replicate to, for example &#34;us-ashburn-1&#34;.
     * 
     */
    public String destinationRegionName() {
        return this.destinationRegionName;
    }
    /**
     * @return The id of the replication policy.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name of the policy.
     * 
     */
    public String name() {
        return this.name;
    }
    public String namespace() {
        return this.namespace;
    }
    public String replicationId() {
        return this.replicationId;
    }
    /**
     * @return The replication status of the policy. If the status is CLIENT_ERROR, once the user fixes the issue described in the status message, the status will become ACTIVE.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return A human-readable description of the status.
     * 
     */
    public String statusMessage() {
        return this.statusMessage;
    }
    /**
     * @return The date when the replication policy was created as per [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Changes made to the source bucket before this time has been replicated.
     * 
     */
    public String timeLastSync() {
        return this.timeLastSync;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicationPolicyResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String bucket;
        private String deleteObjectInDestinationBucket;
        private String destinationBucketName;
        private String destinationRegionName;
        private String id;
        private String name;
        private String namespace;
        private String replicationId;
        private String status;
        private String statusMessage;
        private String timeCreated;
        private String timeLastSync;

        public Builder() {
    	      // Empty
        }

        public Builder(GetReplicationPolicyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.deleteObjectInDestinationBucket = defaults.deleteObjectInDestinationBucket;
    	      this.destinationBucketName = defaults.destinationBucketName;
    	      this.destinationRegionName = defaults.destinationRegionName;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.namespace = defaults.namespace;
    	      this.replicationId = defaults.replicationId;
    	      this.status = defaults.status;
    	      this.statusMessage = defaults.statusMessage;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastSync = defaults.timeLastSync;
        }

        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        public Builder deleteObjectInDestinationBucket(String deleteObjectInDestinationBucket) {
            this.deleteObjectInDestinationBucket = Objects.requireNonNull(deleteObjectInDestinationBucket);
            return this;
        }
        public Builder destinationBucketName(String destinationBucketName) {
            this.destinationBucketName = Objects.requireNonNull(destinationBucketName);
            return this;
        }
        public Builder destinationRegionName(String destinationRegionName) {
            this.destinationRegionName = Objects.requireNonNull(destinationRegionName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        public Builder replicationId(String replicationId) {
            this.replicationId = Objects.requireNonNull(replicationId);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public Builder statusMessage(String statusMessage) {
            this.statusMessage = Objects.requireNonNull(statusMessage);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeLastSync(String timeLastSync) {
            this.timeLastSync = Objects.requireNonNull(timeLastSync);
            return this;
        }        public GetReplicationPolicyResult build() {
            return new GetReplicationPolicyResult(bucket, deleteObjectInDestinationBucket, destinationBucketName, destinationRegionName, id, name, namespace, replicationId, status, statusMessage, timeCreated, timeLastSync);
        }
    }
}
