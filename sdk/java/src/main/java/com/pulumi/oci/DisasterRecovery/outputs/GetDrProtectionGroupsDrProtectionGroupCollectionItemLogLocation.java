// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation {
    /**
     * @return The bucket name inside the object storage namespace.  Example: `bucket_name`
     * 
     */
    private String bucket;
    /**
     * @return The namespace in object storage (Note - this is usually the tenancy name).  Example: `myocitenancy`
     * 
     */
    private String namespace;
    /**
     * @return The object name inside the object storage bucket.  Example: `switchover_plan_executions`
     * 
     */
    private String object;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation() {}
    /**
     * @return The bucket name inside the object storage namespace.  Example: `bucket_name`
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The namespace in object storage (Note - this is usually the tenancy name).  Example: `myocitenancy`
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The object name inside the object storage bucket.  Example: `switchover_plan_executions`
     * 
     */
    public String object() {
        return this.object;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        private String object;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            if (object == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation", "object");
            }
            this.object = object;
            return this;
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation build() {
            final var _resultValue = new GetDrProtectionGroupsDrProtectionGroupCollectionItemLogLocation();
            _resultValue.bucket = bucket;
            _resultValue.namespace = namespace;
            _resultValue.object = object;
            return _resultValue;
        }
    }
}
