// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail {
    /**
     * @return Object Storage bucket name.
     * 
     */
    private String bucket;
    /**
     * @return Object Storage namespace.
     * 
     */
    private String namespace;
    /**
     * @return The type of output location Allowed values are:
     * 
     */
    private String outputType;
    /**
     * @return Object Storage folder name.
     * 
     */
    private String prefix;

    private GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail() {}
    /**
     * @return Object Storage bucket name.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return Object Storage namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The type of output location Allowed values are:
     * 
     */
    public String outputType() {
        return this.outputType;
    }
    /**
     * @return Object Storage folder name.
     * 
     */
    public String prefix() {
        return this.prefix;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        private String outputType;
        private String prefix;
        public Builder() {}
        public Builder(GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
    	      this.outputType = defaults.outputType;
    	      this.prefix = defaults.prefix;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder outputType(String outputType) {
            this.outputType = Objects.requireNonNull(outputType);
            return this;
        }
        @CustomType.Setter
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }
        public GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail build() {
            final var o = new GetDetectAnomalyJobsDetectAnomalyJobCollectionItemOutputDetail();
            o.bucket = bucket;
            o.namespace = namespace;
            o.outputType = outputType;
            o.prefix = prefix;
            return o;
        }
    }
}