// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationsDataTransferMediumDetailObjectStorageBucket {
    /**
     * @return Bucket name.
     * 
     */
    private String bucket;
    /**
     * @return Namespace name of the object store bucket.
     * 
     */
    private String namespace;

    private GetMigrationsDataTransferMediumDetailObjectStorageBucket() {}
    /**
     * @return Bucket name.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return Namespace name of the object store bucket.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsDataTransferMediumDetailObjectStorageBucket defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        public Builder() {}
        public Builder(GetMigrationsDataTransferMediumDetailObjectStorageBucket defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetMigrationsDataTransferMediumDetailObjectStorageBucket", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetMigrationsDataTransferMediumDetailObjectStorageBucket", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        public GetMigrationsDataTransferMediumDetailObjectStorageBucket build() {
            final var _resultValue = new GetMigrationsDataTransferMediumDetailObjectStorageBucket();
            _resultValue.bucket = bucket;
            _resultValue.namespace = namespace;
            return _resultValue;
        }
    }
}
