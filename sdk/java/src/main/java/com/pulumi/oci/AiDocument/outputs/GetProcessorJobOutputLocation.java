// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetProcessorJobOutputLocation {
    /**
     * @return The Object Storage bucket name.
     * 
     */
    private String bucket;
    /**
     * @return The Object Storage namespace.
     * 
     */
    private String namespace;
    /**
     * @return The Object Storage folder name.
     * 
     */
    private String prefix;

    private GetProcessorJobOutputLocation() {}
    /**
     * @return The Object Storage bucket name.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The Object Storage namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The Object Storage folder name.
     * 
     */
    public String prefix() {
        return this.prefix;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProcessorJobOutputLocation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        private String prefix;
        public Builder() {}
        public Builder(GetProcessorJobOutputLocation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
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
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }
        public GetProcessorJobOutputLocation build() {
            final var o = new GetProcessorJobOutputLocation();
            o.bucket = bucket;
            o.namespace = namespace;
            o.prefix = prefix;
            return o;
        }
    }
}