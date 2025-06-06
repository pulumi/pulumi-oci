// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class DatasetInitialImportDatasetConfigurationImportMetadataPathArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatasetInitialImportDatasetConfigurationImportMetadataPathArgs Empty = new DatasetInitialImportDatasetConfigurationImportMetadataPathArgs();

    /**
     * Bucket name
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return Bucket name
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * Bucket namespace name
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return Bucket namespace name
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * Path for the metadata file.
     * 
     */
    @Import(name="path", required=true)
    private Output<String> path;

    /**
     * @return Path for the metadata file.
     * 
     */
    public Output<String> path() {
        return this.path;
    }

    /**
     * The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private DatasetInitialImportDatasetConfigurationImportMetadataPathArgs() {}

    private DatasetInitialImportDatasetConfigurationImportMetadataPathArgs(DatasetInitialImportDatasetConfigurationImportMetadataPathArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.path = $.path;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatasetInitialImportDatasetConfigurationImportMetadataPathArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatasetInitialImportDatasetConfigurationImportMetadataPathArgs $;

        public Builder() {
            $ = new DatasetInitialImportDatasetConfigurationImportMetadataPathArgs();
        }

        public Builder(DatasetInitialImportDatasetConfigurationImportMetadataPathArgs defaults) {
            $ = new DatasetInitialImportDatasetConfigurationImportMetadataPathArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket Bucket name
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket Bucket name
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace Bucket namespace name
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace Bucket namespace name
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param path Path for the metadata file.
         * 
         * @return builder
         * 
         */
        public Builder path(Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path Path for the metadata file.
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param sourceType The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public DatasetInitialImportDatasetConfigurationImportMetadataPathArgs build() {
            if ($.bucket == null) {
                throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfigurationImportMetadataPathArgs", "bucket");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfigurationImportMetadataPathArgs", "namespace");
            }
            if ($.path == null) {
                throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfigurationImportMetadataPathArgs", "path");
            }
            if ($.sourceType == null) {
                throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfigurationImportMetadataPathArgs", "sourceType");
            }
            return $;
        }
    }

}
