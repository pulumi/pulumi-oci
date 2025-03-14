// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ObjectStorage.inputs.ObjectLifecyclePolicyRuleArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ObjectLifecyclePolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final ObjectLifecyclePolicyArgs Empty = new ObjectLifecyclePolicyArgs();

    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * The Object Storage namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Object Storage namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) The bucket&#39;s set of lifecycle policy rules.
     * 
     */
    @Import(name="rules")
    private @Nullable Output<List<ObjectLifecyclePolicyRuleArgs>> rules;

    /**
     * @return (Updatable) The bucket&#39;s set of lifecycle policy rules.
     * 
     */
    public Optional<Output<List<ObjectLifecyclePolicyRuleArgs>>> rules() {
        return Optional.ofNullable(this.rules);
    }

    private ObjectLifecyclePolicyArgs() {}

    private ObjectLifecyclePolicyArgs(ObjectLifecyclePolicyArgs $) {
        this.bucket = $.bucket;
        this.namespace = $.namespace;
        this.rules = $.rules;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ObjectLifecyclePolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ObjectLifecyclePolicyArgs $;

        public Builder() {
            $ = new ObjectLifecyclePolicyArgs();
        }

        public Builder(ObjectLifecyclePolicyArgs defaults) {
            $ = new ObjectLifecyclePolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param rules (Updatable) The bucket&#39;s set of lifecycle policy rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(@Nullable Output<List<ObjectLifecyclePolicyRuleArgs>> rules) {
            $.rules = rules;
            return this;
        }

        /**
         * @param rules (Updatable) The bucket&#39;s set of lifecycle policy rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(List<ObjectLifecyclePolicyRuleArgs> rules) {
            return rules(Output.of(rules));
        }

        /**
         * @param rules (Updatable) The bucket&#39;s set of lifecycle policy rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(ObjectLifecyclePolicyRuleArgs... rules) {
            return rules(List.of(rules));
        }

        public ObjectLifecyclePolicyArgs build() {
            if ($.bucket == null) {
                throw new MissingRequiredPropertyException("ObjectLifecyclePolicyArgs", "bucket");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("ObjectLifecyclePolicyArgs", "namespace");
            }
            return $;
        }
    }

}
