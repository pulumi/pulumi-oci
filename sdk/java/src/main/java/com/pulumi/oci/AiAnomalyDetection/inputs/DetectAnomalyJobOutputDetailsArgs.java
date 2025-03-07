// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DetectAnomalyJobOutputDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DetectAnomalyJobOutputDetailsArgs Empty = new DetectAnomalyJobOutputDetailsArgs();

    /**
     * Object Storage bucket name.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return Object Storage bucket name.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * Object Storage namespace.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return Object Storage namespace.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * The type of output location. Allowed values are:
     * * `OBJECT_STORAGE`: Object store output location.
     * 
     */
    @Import(name="outputType", required=true)
    private Output<String> outputType;

    /**
     * @return The type of output location. Allowed values are:
     * * `OBJECT_STORAGE`: Object store output location.
     * 
     */
    public Output<String> outputType() {
        return this.outputType;
    }

    /**
     * Object Storage folder name.
     * 
     */
    @Import(name="prefix")
    private @Nullable Output<String> prefix;

    /**
     * @return Object Storage folder name.
     * 
     */
    public Optional<Output<String>> prefix() {
        return Optional.ofNullable(this.prefix);
    }

    private DetectAnomalyJobOutputDetailsArgs() {}

    private DetectAnomalyJobOutputDetailsArgs(DetectAnomalyJobOutputDetailsArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.outputType = $.outputType;
        this.prefix = $.prefix;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DetectAnomalyJobOutputDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DetectAnomalyJobOutputDetailsArgs $;

        public Builder() {
            $ = new DetectAnomalyJobOutputDetailsArgs();
        }

        public Builder(DetectAnomalyJobOutputDetailsArgs defaults) {
            $ = new DetectAnomalyJobOutputDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket Object Storage bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
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
         * @param namespace Object Storage namespace.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace Object Storage namespace.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param outputType The type of output location. Allowed values are:
         * * `OBJECT_STORAGE`: Object store output location.
         * 
         * @return builder
         * 
         */
        public Builder outputType(Output<String> outputType) {
            $.outputType = outputType;
            return this;
        }

        /**
         * @param outputType The type of output location. Allowed values are:
         * * `OBJECT_STORAGE`: Object store output location.
         * 
         * @return builder
         * 
         */
        public Builder outputType(String outputType) {
            return outputType(Output.of(outputType));
        }

        /**
         * @param prefix Object Storage folder name.
         * 
         * @return builder
         * 
         */
        public Builder prefix(@Nullable Output<String> prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param prefix Object Storage folder name.
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            return prefix(Output.of(prefix));
        }

        public DetectAnomalyJobOutputDetailsArgs build() {
            if ($.bucket == null) {
                throw new MissingRequiredPropertyException("DetectAnomalyJobOutputDetailsArgs", "bucket");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("DetectAnomalyJobOutputDetailsArgs", "namespace");
            }
            if ($.outputType == null) {
                throw new MissingRequiredPropertyException("DetectAnomalyJobOutputDetailsArgs", "outputType");
            }
            return $;
        }
    }

}
