// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.MeteringComputation.inputs.CustomTableSavedCustomTableArgs;
import java.lang.String;
import java.util.Objects;


public final class CustomTableArgs extends com.pulumi.resources.ResourceArgs {

    public static final CustomTableArgs Empty = new CustomTableArgs();

    /**
     * The compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The custom table for Cost Analysis UI rendering.
     * 
     */
    @Import(name="savedCustomTable", required=true)
    private Output<CustomTableSavedCustomTableArgs> savedCustomTable;

    /**
     * @return (Updatable) The custom table for Cost Analysis UI rendering.
     * 
     */
    public Output<CustomTableSavedCustomTableArgs> savedCustomTable() {
        return this.savedCustomTable;
    }

    /**
     * The associated saved report OCID.
     * 
     */
    @Import(name="savedReportId", required=true)
    private Output<String> savedReportId;

    /**
     * @return The associated saved report OCID.
     * 
     */
    public Output<String> savedReportId() {
        return this.savedReportId;
    }

    private CustomTableArgs() {}

    private CustomTableArgs(CustomTableArgs $) {
        this.compartmentId = $.compartmentId;
        this.savedCustomTable = $.savedCustomTable;
        this.savedReportId = $.savedReportId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CustomTableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CustomTableArgs $;

        public Builder() {
            $ = new CustomTableArgs();
        }

        public Builder(CustomTableArgs defaults) {
            $ = new CustomTableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param savedCustomTable (Updatable) The custom table for Cost Analysis UI rendering.
         * 
         * @return builder
         * 
         */
        public Builder savedCustomTable(Output<CustomTableSavedCustomTableArgs> savedCustomTable) {
            $.savedCustomTable = savedCustomTable;
            return this;
        }

        /**
         * @param savedCustomTable (Updatable) The custom table for Cost Analysis UI rendering.
         * 
         * @return builder
         * 
         */
        public Builder savedCustomTable(CustomTableSavedCustomTableArgs savedCustomTable) {
            return savedCustomTable(Output.of(savedCustomTable));
        }

        /**
         * @param savedReportId The associated saved report OCID.
         * 
         * @return builder
         * 
         */
        public Builder savedReportId(Output<String> savedReportId) {
            $.savedReportId = savedReportId;
            return this;
        }

        /**
         * @param savedReportId The associated saved report OCID.
         * 
         * @return builder
         * 
         */
        public Builder savedReportId(String savedReportId) {
            return savedReportId(Output.of(savedReportId));
        }

        public CustomTableArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.savedCustomTable = Objects.requireNonNull($.savedCustomTable, "expected parameter 'savedCustomTable' to be non-null");
            $.savedReportId = Objects.requireNonNull($.savedReportId, "expected parameter 'savedReportId' to be non-null");
            return $;
        }
    }

}