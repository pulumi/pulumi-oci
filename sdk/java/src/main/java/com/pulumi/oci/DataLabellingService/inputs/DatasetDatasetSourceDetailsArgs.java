// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatasetDatasetSourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatasetDatasetSourceDetailsArgs Empty = new DatasetDatasetSourceDetailsArgs();

    /**
     * The object storage bucket that contains the dataset data source.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return The object storage bucket that contains the dataset data source.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * The namespace of the bucket that contains the dataset data source.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The namespace of the bucket that contains the dataset data source.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
     * 
     */
    @Import(name="prefix")
    private @Nullable Output<String> prefix;

    /**
     * @return A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
     * 
     */
    public Optional<Output<String>> prefix() {
        return Optional.ofNullable(this.prefix);
    }

    /**
     * The source type. OBJECT_STORAGE allows the user to describe where in object storage the dataset is.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return The source type. OBJECT_STORAGE allows the user to describe where in object storage the dataset is.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private DatasetDatasetSourceDetailsArgs() {}

    private DatasetDatasetSourceDetailsArgs(DatasetDatasetSourceDetailsArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.prefix = $.prefix;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatasetDatasetSourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatasetDatasetSourceDetailsArgs $;

        public Builder() {
            $ = new DatasetDatasetSourceDetailsArgs();
        }

        public Builder(DatasetDatasetSourceDetailsArgs defaults) {
            $ = new DatasetDatasetSourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The object storage bucket that contains the dataset data source.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The object storage bucket that contains the dataset data source.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace The namespace of the bucket that contains the dataset data source.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The namespace of the bucket that contains the dataset data source.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param prefix A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
         * 
         * @return builder
         * 
         */
        public Builder prefix(@Nullable Output<String> prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param prefix A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            return prefix(Output.of(prefix));
        }

        /**
         * @param sourceType The source type. OBJECT_STORAGE allows the user to describe where in object storage the dataset is.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType The source type. OBJECT_STORAGE allows the user to describe where in object storage the dataset is.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public DatasetDatasetSourceDetailsArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            $.sourceType = Objects.requireNonNull($.sourceType, "expected parameter 'sourceType' to be non-null");
            return $;
        }
    }

}