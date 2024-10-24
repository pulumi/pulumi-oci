// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Audit;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;


public final class ConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigurationArgs Empty = new ConfigurationArgs();

    /**
     * ID of the root compartment (tenancy)
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return ID of the root compartment (tenancy)
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="retentionPeriodDays", required=true)
    private Output<Integer> retentionPeriodDays;

    /**
     * @return (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Integer> retentionPeriodDays() {
        return this.retentionPeriodDays;
    }

    private ConfigurationArgs() {}

    private ConfigurationArgs(ConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
        this.retentionPeriodDays = $.retentionPeriodDays;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigurationArgs $;

        public Builder() {
            $ = new ConfigurationArgs();
        }

        public Builder(ConfigurationArgs defaults) {
            $ = new ConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId ID of the root compartment (tenancy)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId ID of the root compartment (tenancy)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param retentionPeriodDays (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodDays(Output<Integer> retentionPeriodDays) {
            $.retentionPeriodDays = retentionPeriodDays;
            return this;
        }

        /**
         * @param retentionPeriodDays (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodDays(Integer retentionPeriodDays) {
            return retentionPeriodDays(Output.of(retentionPeriodDays));
        }

        public ConfigurationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ConfigurationArgs", "compartmentId");
            }
            if ($.retentionPeriodDays == null) {
                throw new MissingRequiredPropertyException("ConfigurationArgs", "retentionPeriodDays");
            }
            return $;
        }
    }

}
