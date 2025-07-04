// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class SchedulerDefinitionRunBookInputParameterArgumentContentArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulerDefinitionRunBookInputParameterArgumentContentArgs Empty = new SchedulerDefinitionRunBookInputParameterArgumentContentArgs();

    /**
     * (Updatable) Bucket Name.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return (Updatable) Bucket Name.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * (Updatable) md5 checksum of the artifact.
     * 
     */
    @Import(name="checksum", required=true)
    private Output<String> checksum;

    /**
     * @return (Updatable) md5 checksum of the artifact.
     * 
     */
    public Output<String> checksum() {
        return this.checksum;
    }

    /**
     * (Updatable) Namespace.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) Namespace.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) Object Name.
     * 
     */
    @Import(name="object", required=true)
    private Output<String> object;

    /**
     * @return (Updatable) Object Name.
     * 
     */
    public Output<String> object() {
        return this.object;
    }

    /**
     * (Updatable) Content Source type details.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return (Updatable) Content Source type details.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private SchedulerDefinitionRunBookInputParameterArgumentContentArgs() {}

    private SchedulerDefinitionRunBookInputParameterArgumentContentArgs(SchedulerDefinitionRunBookInputParameterArgumentContentArgs $) {
        this.bucket = $.bucket;
        this.checksum = $.checksum;
        this.namespace = $.namespace;
        this.object = $.object;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulerDefinitionRunBookInputParameterArgumentContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulerDefinitionRunBookInputParameterArgumentContentArgs $;

        public Builder() {
            $ = new SchedulerDefinitionRunBookInputParameterArgumentContentArgs();
        }

        public Builder(SchedulerDefinitionRunBookInputParameterArgumentContentArgs defaults) {
            $ = new SchedulerDefinitionRunBookInputParameterArgumentContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket (Updatable) Bucket Name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket (Updatable) Bucket Name.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param checksum (Updatable) md5 checksum of the artifact.
         * 
         * @return builder
         * 
         */
        public Builder checksum(Output<String> checksum) {
            $.checksum = checksum;
            return this;
        }

        /**
         * @param checksum (Updatable) md5 checksum of the artifact.
         * 
         * @return builder
         * 
         */
        public Builder checksum(String checksum) {
            return checksum(Output.of(checksum));
        }

        /**
         * @param namespace (Updatable) Namespace.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) Namespace.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object (Updatable) Object Name.
         * 
         * @return builder
         * 
         */
        public Builder object(Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object (Updatable) Object Name.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param sourceType (Updatable) Content Source type details.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType (Updatable) Content Source type details.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public SchedulerDefinitionRunBookInputParameterArgumentContentArgs build() {
            if ($.bucket == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentContentArgs", "bucket");
            }
            if ($.checksum == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentContentArgs", "checksum");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentContentArgs", "namespace");
            }
            if ($.object == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentContentArgs", "object");
            }
            if ($.sourceType == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentContentArgs", "sourceType");
            }
            return $;
        }
    }

}
