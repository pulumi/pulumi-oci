// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ScheduleResultLocationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ScheduleResultLocationArgs Empty = new ScheduleResultLocationArgs();

    /**
     * (Updatable) The bucket name where usage or cost CSVs will be uploaded.
     * 
     */
    @Import(name="bucket", required=true)
    private Output<String> bucket;

    /**
     * @return (Updatable) The bucket name where usage or cost CSVs will be uploaded.
     * 
     */
    public Output<String> bucket() {
        return this.bucket;
    }

    /**
     * (Updatable) Defines the type of location where the usage or cost CSVs will be stored.
     * 
     */
    @Import(name="locationType", required=true)
    private Output<String> locationType;

    /**
     * @return (Updatable) Defines the type of location where the usage or cost CSVs will be stored.
     * 
     */
    public Output<String> locationType() {
        return this.locationType;
    }

    /**
     * (Updatable) The namespace needed to determine the object storage bucket.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) The namespace needed to determine the object storage bucket.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) The destination Object Store Region specified by the customer.
     * 
     */
    @Import(name="region", required=true)
    private Output<String> region;

    /**
     * @return (Updatable) The destination Object Store Region specified by the customer.
     * 
     */
    public Output<String> region() {
        return this.region;
    }

    private ScheduleResultLocationArgs() {}

    private ScheduleResultLocationArgs(ScheduleResultLocationArgs $) {
        this.bucket = $.bucket;
        this.locationType = $.locationType;
        this.namespace = $.namespace;
        this.region = $.region;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScheduleResultLocationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScheduleResultLocationArgs $;

        public Builder() {
            $ = new ScheduleResultLocationArgs();
        }

        public Builder(ScheduleResultLocationArgs defaults) {
            $ = new ScheduleResultLocationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket (Updatable) The bucket name where usage or cost CSVs will be uploaded.
         * 
         * @return builder
         * 
         */
        public Builder bucket(Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket (Updatable) The bucket name where usage or cost CSVs will be uploaded.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param locationType (Updatable) Defines the type of location where the usage or cost CSVs will be stored.
         * 
         * @return builder
         * 
         */
        public Builder locationType(Output<String> locationType) {
            $.locationType = locationType;
            return this;
        }

        /**
         * @param locationType (Updatable) Defines the type of location where the usage or cost CSVs will be stored.
         * 
         * @return builder
         * 
         */
        public Builder locationType(String locationType) {
            return locationType(Output.of(locationType));
        }

        /**
         * @param namespace (Updatable) The namespace needed to determine the object storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) The namespace needed to determine the object storage bucket.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param region (Updatable) The destination Object Store Region specified by the customer.
         * 
         * @return builder
         * 
         */
        public Builder region(Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region (Updatable) The destination Object Store Region specified by the customer.
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        public ScheduleResultLocationArgs build() {
            if ($.bucket == null) {
                throw new MissingRequiredPropertyException("ScheduleResultLocationArgs", "bucket");
            }
            if ($.locationType == null) {
                throw new MissingRequiredPropertyException("ScheduleResultLocationArgs", "locationType");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("ScheduleResultLocationArgs", "namespace");
            }
            if ($.region == null) {
                throw new MissingRequiredPropertyException("ScheduleResultLocationArgs", "region");
            }
            return $;
        }
    }

}
