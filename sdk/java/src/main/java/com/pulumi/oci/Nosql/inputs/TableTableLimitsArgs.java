// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TableTableLimitsArgs extends com.pulumi.resources.ResourceArgs {

    public static final TableTableLimitsArgs Empty = new TableTableLimitsArgs();

    /**
     * (Updatable) The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    @Import(name="capacityMode")
    private @Nullable Output<String> capacityMode;

    /**
     * @return (Updatable) The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    public Optional<Output<String>> capacityMode() {
        return Optional.ofNullable(this.capacityMode);
    }

    /**
     * (Updatable) Maximum sustained read throughput limit for the table.
     * 
     */
    @Import(name="maxReadUnits", required=true)
    private Output<Integer> maxReadUnits;

    /**
     * @return (Updatable) Maximum sustained read throughput limit for the table.
     * 
     */
    public Output<Integer> maxReadUnits() {
        return this.maxReadUnits;
    }

    /**
     * (Updatable) Maximum size of storage used by the table.
     * 
     */
    @Import(name="maxStorageInGbs", required=true)
    private Output<Integer> maxStorageInGbs;

    /**
     * @return (Updatable) Maximum size of storage used by the table.
     * 
     */
    public Output<Integer> maxStorageInGbs() {
        return this.maxStorageInGbs;
    }

    /**
     * (Updatable) Maximum sustained write throughput limit for the table.
     * 
     * ** IMPORTANT **
     * Any change to a property that is not identified as &#34;Updateable&#34; will force the destruction and recreation of the resource with the new property values.
     * 
     */
    @Import(name="maxWriteUnits", required=true)
    private Output<Integer> maxWriteUnits;

    /**
     * @return (Updatable) Maximum sustained write throughput limit for the table.
     * 
     * ** IMPORTANT **
     * Any change to a property that is not identified as &#34;Updateable&#34; will force the destruction and recreation of the resource with the new property values.
     * 
     */
    public Output<Integer> maxWriteUnits() {
        return this.maxWriteUnits;
    }

    private TableTableLimitsArgs() {}

    private TableTableLimitsArgs(TableTableLimitsArgs $) {
        this.capacityMode = $.capacityMode;
        this.maxReadUnits = $.maxReadUnits;
        this.maxStorageInGbs = $.maxStorageInGbs;
        this.maxWriteUnits = $.maxWriteUnits;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TableTableLimitsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TableTableLimitsArgs $;

        public Builder() {
            $ = new TableTableLimitsArgs();
        }

        public Builder(TableTableLimitsArgs defaults) {
            $ = new TableTableLimitsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capacityMode (Updatable) The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
         * 
         * @return builder
         * 
         */
        public Builder capacityMode(@Nullable Output<String> capacityMode) {
            $.capacityMode = capacityMode;
            return this;
        }

        /**
         * @param capacityMode (Updatable) The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
         * 
         * @return builder
         * 
         */
        public Builder capacityMode(String capacityMode) {
            return capacityMode(Output.of(capacityMode));
        }

        /**
         * @param maxReadUnits (Updatable) Maximum sustained read throughput limit for the table.
         * 
         * @return builder
         * 
         */
        public Builder maxReadUnits(Output<Integer> maxReadUnits) {
            $.maxReadUnits = maxReadUnits;
            return this;
        }

        /**
         * @param maxReadUnits (Updatable) Maximum sustained read throughput limit for the table.
         * 
         * @return builder
         * 
         */
        public Builder maxReadUnits(Integer maxReadUnits) {
            return maxReadUnits(Output.of(maxReadUnits));
        }

        /**
         * @param maxStorageInGbs (Updatable) Maximum size of storage used by the table.
         * 
         * @return builder
         * 
         */
        public Builder maxStorageInGbs(Output<Integer> maxStorageInGbs) {
            $.maxStorageInGbs = maxStorageInGbs;
            return this;
        }

        /**
         * @param maxStorageInGbs (Updatable) Maximum size of storage used by the table.
         * 
         * @return builder
         * 
         */
        public Builder maxStorageInGbs(Integer maxStorageInGbs) {
            return maxStorageInGbs(Output.of(maxStorageInGbs));
        }

        /**
         * @param maxWriteUnits (Updatable) Maximum sustained write throughput limit for the table.
         * 
         * ** IMPORTANT **
         * Any change to a property that is not identified as &#34;Updateable&#34; will force the destruction and recreation of the resource with the new property values.
         * 
         * @return builder
         * 
         */
        public Builder maxWriteUnits(Output<Integer> maxWriteUnits) {
            $.maxWriteUnits = maxWriteUnits;
            return this;
        }

        /**
         * @param maxWriteUnits (Updatable) Maximum sustained write throughput limit for the table.
         * 
         * ** IMPORTANT **
         * Any change to a property that is not identified as &#34;Updateable&#34; will force the destruction and recreation of the resource with the new property values.
         * 
         * @return builder
         * 
         */
        public Builder maxWriteUnits(Integer maxWriteUnits) {
            return maxWriteUnits(Output.of(maxWriteUnits));
        }

        public TableTableLimitsArgs build() {
            if ($.maxReadUnits == null) {
                throw new MissingRequiredPropertyException("TableTableLimitsArgs", "maxReadUnits");
            }
            if ($.maxStorageInGbs == null) {
                throw new MissingRequiredPropertyException("TableTableLimitsArgs", "maxStorageInGbs");
            }
            if ($.maxWriteUnits == null) {
                throw new MissingRequiredPropertyException("TableTableLimitsArgs", "maxWriteUnits");
            }
            return $;
        }
    }

}
