// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class MigrationDataTransferMediumDetailsObjectStorageDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationDataTransferMediumDetailsObjectStorageDetailsArgs Empty = new MigrationDataTransferMediumDetailsObjectStorageDetailsArgs();

    /**
     * (Updatable) Bucket name.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return (Updatable) Bucket name.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * (Updatable) Namespace name of the object store bucket.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) Namespace name of the object store bucket.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private MigrationDataTransferMediumDetailsObjectStorageDetailsArgs() {}

    private MigrationDataTransferMediumDetailsObjectStorageDetailsArgs(MigrationDataTransferMediumDetailsObjectStorageDetailsArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationDataTransferMediumDetailsObjectStorageDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationDataTransferMediumDetailsObjectStorageDetailsArgs $;

        public Builder() {
            $ = new MigrationDataTransferMediumDetailsObjectStorageDetailsArgs();
        }

        public Builder(MigrationDataTransferMediumDetailsObjectStorageDetailsArgs defaults) {
            $ = new MigrationDataTransferMediumDetailsObjectStorageDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket (Updatable) Bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket (Updatable) Bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace (Updatable) Namespace name of the object store bucket.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) Namespace name of the object store bucket.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public MigrationDataTransferMediumDetailsObjectStorageDetailsArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}