// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProcessorJobInputLocationObjectLocationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ProcessorJobInputLocationObjectLocationArgs Empty = new ProcessorJobInputLocationObjectLocationArgs();

    /**
     * The Object Storage bucket name.
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return The Object Storage bucket name.
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * The Object Storage namespace name.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Object Storage namespace name.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * The Object Storage object name.
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return The Object Storage object name.
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    private ProcessorJobInputLocationObjectLocationArgs() {}

    private ProcessorJobInputLocationObjectLocationArgs(ProcessorJobInputLocationObjectLocationArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.object = $.object;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProcessorJobInputLocationObjectLocationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProcessorJobInputLocationObjectLocationArgs $;

        public Builder() {
            $ = new ProcessorJobInputLocationObjectLocationArgs();
        }

        public Builder(ProcessorJobInputLocationObjectLocationArgs defaults) {
            $ = new ProcessorJobInputLocationObjectLocationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The Object Storage bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The Object Storage bucket name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace The Object Storage namespace name.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Object Storage namespace name.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object The Object Storage object name.
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object The Object Storage object name.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        public ProcessorJobInputLocationObjectLocationArgs build() {
            return $;
        }
    }

}
