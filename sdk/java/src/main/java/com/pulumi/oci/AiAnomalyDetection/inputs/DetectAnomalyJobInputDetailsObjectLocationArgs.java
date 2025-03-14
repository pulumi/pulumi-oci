// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DetectAnomalyJobInputDetailsObjectLocationArgs extends com.pulumi.resources.ResourceArgs {

    public static final DetectAnomalyJobInputDetailsObjectLocationArgs Empty = new DetectAnomalyJobInputDetailsObjectLocationArgs();

    /**
     * Object Storage bucket name.
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return Object Storage bucket name.
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * Object Storage namespace name.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return Object Storage namespace name.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * Object Storage object name.
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return Object Storage object name.
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    private DetectAnomalyJobInputDetailsObjectLocationArgs() {}

    private DetectAnomalyJobInputDetailsObjectLocationArgs(DetectAnomalyJobInputDetailsObjectLocationArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.object = $.object;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DetectAnomalyJobInputDetailsObjectLocationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DetectAnomalyJobInputDetailsObjectLocationArgs $;

        public Builder() {
            $ = new DetectAnomalyJobInputDetailsObjectLocationArgs();
        }

        public Builder(DetectAnomalyJobInputDetailsObjectLocationArgs defaults) {
            $ = new DetectAnomalyJobInputDetailsObjectLocationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket Object Storage bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket Object Storage bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace Object Storage namespace name.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace Object Storage namespace name.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object Object Storage object name.
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object Object Storage object name.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        public DetectAnomalyJobInputDetailsObjectLocationArgs build() {
            return $;
        }
    }

}
