// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class StorageObjectSourceUriDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final StorageObjectSourceUriDetailsArgs Empty = new StorageObjectSourceUriDetailsArgs();

    /**
     * The name of the bucket for the source object.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return The name of the bucket for the source object.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * The entity tag to match the target object.
     * 
     */
    @Import(name="destinationObjectIfMatchEtag")
    private @Nullable Output<String> destinationObjectIfMatchEtag;

    /**
     * @return The entity tag to match the target object.
     * 
     */
    public Optional<Output<String>> destinationObjectIfMatchEtag() {
        return Optional.ofNullable(this.destinationObjectIfMatchEtag);
    }

    /**
     * The entity tag to not match the target object.
     * 
     */
    @Import(name="destinationObjectIfNoneMatchEtag")
    private @Nullable Output<String> destinationObjectIfNoneMatchEtag;

    /**
     * @return The entity tag to not match the target object.
     * 
     */
    public Optional<Output<String>> destinationObjectIfNoneMatchEtag() {
        return Optional.ofNullable(this.destinationObjectIfNoneMatchEtag);
    }

    /**
     * The top-level namespace of the source object.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The top-level namespace of the source object.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * The name of the source object.
     * 
     */
    @Import(name="object", required=true)
    private Output<String> object;

    /**
     * @return The name of the source object.
     * 
     */
    public Output<String> object() {
        return this.object;
    }

    /**
     * The region of the source object.
     * 
     */
    @Import(name="region", required=true)
    private Output<String> region;

    /**
     * @return The region of the source object.
     * 
     */
    public Output<String> region() {
        return this.region;
    }

    /**
     * The entity tag to match the source object.
     * 
     */
    @Import(name="sourceObjectIfMatchEtag")
    private @Nullable Output<String> sourceObjectIfMatchEtag;

    /**
     * @return The entity tag to match the source object.
     * 
     */
    public Optional<Output<String>> sourceObjectIfMatchEtag() {
        return Optional.ofNullable(this.sourceObjectIfMatchEtag);
    }

    /**
     * The version id of the object to be restored.
     * 
     */
    @Import(name="sourceVersionId")
    private @Nullable Output<String> sourceVersionId;

    /**
     * @return The version id of the object to be restored.
     * 
     */
    public Optional<Output<String>> sourceVersionId() {
        return Optional.ofNullable(this.sourceVersionId);
    }

    private StorageObjectSourceUriDetailsArgs() {}

    private StorageObjectSourceUriDetailsArgs(StorageObjectSourceUriDetailsArgs $) {
        this.bucket = $.bucket;
        this.destinationObjectIfMatchEtag = $.destinationObjectIfMatchEtag;
        this.destinationObjectIfNoneMatchEtag = $.destinationObjectIfNoneMatchEtag;
        this.namespace = $.namespace;
        this.object = $.object;
        this.region = $.region;
        this.sourceObjectIfMatchEtag = $.sourceObjectIfMatchEtag;
        this.sourceVersionId = $.sourceVersionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(StorageObjectSourceUriDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private StorageObjectSourceUriDetailsArgs $;

        public Builder() {
            $ = new StorageObjectSourceUriDetailsArgs();
        }

        public Builder(StorageObjectSourceUriDetailsArgs defaults) {
            $ = new StorageObjectSourceUriDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The name of the bucket for the source object.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The name of the bucket for the source object.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param destinationObjectIfMatchEtag The entity tag to match the target object.
         * 
         * @return builder
         * 
         */
        public Builder destinationObjectIfMatchEtag(@Nullable Output<String> destinationObjectIfMatchEtag) {
            $.destinationObjectIfMatchEtag = destinationObjectIfMatchEtag;
            return this;
        }

        /**
         * @param destinationObjectIfMatchEtag The entity tag to match the target object.
         * 
         * @return builder
         * 
         */
        public Builder destinationObjectIfMatchEtag(String destinationObjectIfMatchEtag) {
            return destinationObjectIfMatchEtag(Output.of(destinationObjectIfMatchEtag));
        }

        /**
         * @param destinationObjectIfNoneMatchEtag The entity tag to not match the target object.
         * 
         * @return builder
         * 
         */
        public Builder destinationObjectIfNoneMatchEtag(@Nullable Output<String> destinationObjectIfNoneMatchEtag) {
            $.destinationObjectIfNoneMatchEtag = destinationObjectIfNoneMatchEtag;
            return this;
        }

        /**
         * @param destinationObjectIfNoneMatchEtag The entity tag to not match the target object.
         * 
         * @return builder
         * 
         */
        public Builder destinationObjectIfNoneMatchEtag(String destinationObjectIfNoneMatchEtag) {
            return destinationObjectIfNoneMatchEtag(Output.of(destinationObjectIfNoneMatchEtag));
        }

        /**
         * @param namespace The top-level namespace of the source object.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The top-level namespace of the source object.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object The name of the source object.
         * 
         * @return builder
         * 
         */
        public Builder object(Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object The name of the source object.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param region The region of the source object.
         * 
         * @return builder
         * 
         */
        public Builder region(Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region The region of the source object.
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param sourceObjectIfMatchEtag The entity tag to match the source object.
         * 
         * @return builder
         * 
         */
        public Builder sourceObjectIfMatchEtag(@Nullable Output<String> sourceObjectIfMatchEtag) {
            $.sourceObjectIfMatchEtag = sourceObjectIfMatchEtag;
            return this;
        }

        /**
         * @param sourceObjectIfMatchEtag The entity tag to match the source object.
         * 
         * @return builder
         * 
         */
        public Builder sourceObjectIfMatchEtag(String sourceObjectIfMatchEtag) {
            return sourceObjectIfMatchEtag(Output.of(sourceObjectIfMatchEtag));
        }

        /**
         * @param sourceVersionId The version id of the object to be restored.
         * 
         * @return builder
         * 
         */
        public Builder sourceVersionId(@Nullable Output<String> sourceVersionId) {
            $.sourceVersionId = sourceVersionId;
            return this;
        }

        /**
         * @param sourceVersionId The version id of the object to be restored.
         * 
         * @return builder
         * 
         */
        public Builder sourceVersionId(String sourceVersionId) {
            return sourceVersionId(Output.of(sourceVersionId));
        }

        public StorageObjectSourceUriDetailsArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            $.object = Objects.requireNonNull($.object, "expected parameter 'object' to be non-null");
            $.region = Objects.requireNonNull($.region, "expected parameter 'region' to be non-null");
            return $;
        }
    }

}