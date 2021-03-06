// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class JobProgressPhaseLogLocation {
    /**
     * @return Name of the bucket containing the log file.
     * 
     */
    private final @Nullable String bucket;
    /**
     * @return Object Storage namespace.
     * 
     */
    private final @Nullable String namespace;
    /**
     * @return Name of the object (regular expression is allowed)
     * 
     */
    private final @Nullable String object;

    @CustomType.Constructor
    private JobProgressPhaseLogLocation(
        @CustomType.Parameter("bucket") @Nullable String bucket,
        @CustomType.Parameter("namespace") @Nullable String namespace,
        @CustomType.Parameter("object") @Nullable String object) {
        this.bucket = bucket;
        this.namespace = namespace;
        this.object = object;
    }

    /**
     * @return Name of the bucket containing the log file.
     * 
     */
    public Optional<String> bucket() {
        return Optional.ofNullable(this.bucket);
    }
    /**
     * @return Object Storage namespace.
     * 
     */
    public Optional<String> namespace() {
        return Optional.ofNullable(this.namespace);
    }
    /**
     * @return Name of the object (regular expression is allowed)
     * 
     */
    public Optional<String> object() {
        return Optional.ofNullable(this.object);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(JobProgressPhaseLogLocation defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String bucket;
        private @Nullable String namespace;
        private @Nullable String object;

        public Builder() {
    	      // Empty
        }

        public Builder(JobProgressPhaseLogLocation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
        }

        public Builder bucket(@Nullable String bucket) {
            this.bucket = bucket;
            return this;
        }
        public Builder namespace(@Nullable String namespace) {
            this.namespace = namespace;
            return this;
        }
        public Builder object(@Nullable String object) {
            this.object = object;
            return this;
        }        public JobProgressPhaseLogLocation build() {
            return new JobProgressPhaseLogLocation(bucket, namespace, object);
        }
    }
}
