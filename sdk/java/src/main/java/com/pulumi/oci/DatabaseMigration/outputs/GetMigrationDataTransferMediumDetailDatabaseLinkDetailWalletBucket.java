// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket {
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

    private GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket() {}
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

    public static Builder builder(GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        public Builder() {}
        public Builder(GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
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
        public GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket build() {
            final var o = new GetMigrationDataTransferMediumDetailDatabaseLinkDetailWalletBucket();
            o.bucket = bucket;
            o.namespace = namespace;
            return o;
        }
    }
}