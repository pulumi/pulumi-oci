// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LogAnalyticsUnprocessedDataBucketManagementArgs extends com.pulumi.resources.ResourceArgs {

    public static final LogAnalyticsUnprocessedDataBucketManagementArgs Empty = new LogAnalyticsUnprocessedDataBucketManagementArgs();

    /**
     * Name of the Object Storage bucket.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return Name of the Object Storage bucket.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * Flag that specifies if this configuration is enabled or not.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return Flag that specifies if this configuration is enabled or not.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private LogAnalyticsUnprocessedDataBucketManagementArgs() {}

    private LogAnalyticsUnprocessedDataBucketManagementArgs(LogAnalyticsUnprocessedDataBucketManagementArgs $) {
        this.bucket = $.bucket;
        this.isEnabled = $.isEnabled;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LogAnalyticsUnprocessedDataBucketManagementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LogAnalyticsUnprocessedDataBucketManagementArgs $;

        public Builder() {
            $ = new LogAnalyticsUnprocessedDataBucketManagementArgs();
        }

        public Builder(LogAnalyticsUnprocessedDataBucketManagementArgs defaults) {
            $ = new LogAnalyticsUnprocessedDataBucketManagementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket Name of the Object Storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket Name of the Object Storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param isEnabled Flag that specifies if this configuration is enabled or not.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled Flag that specifies if this configuration is enabled or not.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public LogAnalyticsUnprocessedDataBucketManagementArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}