// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTableTableLimit {
    /**
     * @return The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    private final String capacityMode;
    /**
     * @return Maximum sustained read throughput limit for the table.
     * 
     */
    private final Integer maxReadUnits;
    /**
     * @return Maximum size of storage used by the table.
     * 
     */
    private final Integer maxStorageInGbs;
    /**
     * @return Maximum sustained write throughput limit for the table.
     * 
     */
    private final Integer maxWriteUnits;

    @CustomType.Constructor
    private GetTableTableLimit(
        @CustomType.Parameter("capacityMode") String capacityMode,
        @CustomType.Parameter("maxReadUnits") Integer maxReadUnits,
        @CustomType.Parameter("maxStorageInGbs") Integer maxStorageInGbs,
        @CustomType.Parameter("maxWriteUnits") Integer maxWriteUnits) {
        this.capacityMode = capacityMode;
        this.maxReadUnits = maxReadUnits;
        this.maxStorageInGbs = maxStorageInGbs;
        this.maxWriteUnits = maxWriteUnits;
    }

    /**
     * @return The capacity mode of the table.  If capacityMode = ON_DEMAND, maxReadUnits and maxWriteUnits are not used, and both will have the value of zero.
     * 
     */
    public String capacityMode() {
        return this.capacityMode;
    }
    /**
     * @return Maximum sustained read throughput limit for the table.
     * 
     */
    public Integer maxReadUnits() {
        return this.maxReadUnits;
    }
    /**
     * @return Maximum size of storage used by the table.
     * 
     */
    public Integer maxStorageInGbs() {
        return this.maxStorageInGbs;
    }
    /**
     * @return Maximum sustained write throughput limit for the table.
     * 
     */
    public Integer maxWriteUnits() {
        return this.maxWriteUnits;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTableTableLimit defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String capacityMode;
        private Integer maxReadUnits;
        private Integer maxStorageInGbs;
        private Integer maxWriteUnits;

        public Builder() {
    	      // Empty
        }

        public Builder(GetTableTableLimit defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.capacityMode = defaults.capacityMode;
    	      this.maxReadUnits = defaults.maxReadUnits;
    	      this.maxStorageInGbs = defaults.maxStorageInGbs;
    	      this.maxWriteUnits = defaults.maxWriteUnits;
        }

        public Builder capacityMode(String capacityMode) {
            this.capacityMode = Objects.requireNonNull(capacityMode);
            return this;
        }
        public Builder maxReadUnits(Integer maxReadUnits) {
            this.maxReadUnits = Objects.requireNonNull(maxReadUnits);
            return this;
        }
        public Builder maxStorageInGbs(Integer maxStorageInGbs) {
            this.maxStorageInGbs = Objects.requireNonNull(maxStorageInGbs);
            return this;
        }
        public Builder maxWriteUnits(Integer maxWriteUnits) {
            this.maxWriteUnits = Objects.requireNonNull(maxWriteUnits);
            return this;
        }        public GetTableTableLimit build() {
            return new GetTableTableLimit(capacityMode, maxReadUnits, maxStorageInGbs, maxWriteUnits);
        }
    }
}
