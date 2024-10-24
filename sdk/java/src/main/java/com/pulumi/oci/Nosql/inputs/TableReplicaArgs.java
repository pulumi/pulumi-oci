// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TableReplicaArgs extends com.pulumi.resources.ResourceArgs {

    public static final TableReplicaArgs Empty = new TableReplicaArgs();

    /**
     * The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    @Import(name="capacityMode")
    private @Nullable Output<String> capacityMode;

    /**
     * @return The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    public Optional<Output<String>> capacityMode() {
        return Optional.ofNullable(this.capacityMode);
    }

    /**
     * A message describing the current state in more detail.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Maximum sustained write throughput limit for the table.
     * 
     */
    @Import(name="maxWriteUnits")
    private @Nullable Output<Integer> maxWriteUnits;

    /**
     * @return Maximum sustained write throughput limit for the table.
     * 
     */
    public Optional<Output<Integer>> maxWriteUnits() {
        return Optional.ofNullable(this.maxWriteUnits);
    }

    /**
     * A customer-facing region identifier
     * 
     */
    @Import(name="region")
    private @Nullable Output<String> region;

    /**
     * @return A customer-facing region identifier
     * 
     */
    public Optional<Output<String>> region() {
        return Optional.ofNullable(this.region);
    }

    /**
     * The state of a table.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The state of a table.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the replica table
     * 
     */
    @Import(name="tableId")
    private @Nullable Output<String> tableId;

    /**
     * @return The OCID of the replica table
     * 
     */
    public Optional<Output<String>> tableId() {
        return Optional.ofNullable(this.tableId);
    }

    private TableReplicaArgs() {}

    private TableReplicaArgs(TableReplicaArgs $) {
        this.capacityMode = $.capacityMode;
        this.lifecycleDetails = $.lifecycleDetails;
        this.maxWriteUnits = $.maxWriteUnits;
        this.region = $.region;
        this.state = $.state;
        this.tableId = $.tableId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TableReplicaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TableReplicaArgs $;

        public Builder() {
            $ = new TableReplicaArgs();
        }

        public Builder(TableReplicaArgs defaults) {
            $ = new TableReplicaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capacityMode The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
         * 
         * @return builder
         * 
         */
        public Builder capacityMode(@Nullable Output<String> capacityMode) {
            $.capacityMode = capacityMode;
            return this;
        }

        /**
         * @param capacityMode The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
         * 
         * @return builder
         * 
         */
        public Builder capacityMode(String capacityMode) {
            return capacityMode(Output.of(capacityMode));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param maxWriteUnits Maximum sustained write throughput limit for the table.
         * 
         * @return builder
         * 
         */
        public Builder maxWriteUnits(@Nullable Output<Integer> maxWriteUnits) {
            $.maxWriteUnits = maxWriteUnits;
            return this;
        }

        /**
         * @param maxWriteUnits Maximum sustained write throughput limit for the table.
         * 
         * @return builder
         * 
         */
        public Builder maxWriteUnits(Integer maxWriteUnits) {
            return maxWriteUnits(Output.of(maxWriteUnits));
        }

        /**
         * @param region A customer-facing region identifier
         * 
         * @return builder
         * 
         */
        public Builder region(@Nullable Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region A customer-facing region identifier
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param state The state of a table.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The state of a table.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param tableId The OCID of the replica table
         * 
         * @return builder
         * 
         */
        public Builder tableId(@Nullable Output<String> tableId) {
            $.tableId = tableId;
            return this;
        }

        /**
         * @param tableId The OCID of the replica table
         * 
         * @return builder
         * 
         */
        public Builder tableId(String tableId) {
            return tableId(Output.of(tableId));
        }

        public TableReplicaArgs build() {
            return $;
        }
    }

}
