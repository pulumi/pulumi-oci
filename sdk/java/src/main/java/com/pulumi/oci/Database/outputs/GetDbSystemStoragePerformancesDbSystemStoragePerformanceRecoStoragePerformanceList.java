// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance;
import com.pulumi.oci.Database.outputs.GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList {
    /**
     * @return Representation of disk performance detail parameters.
     * 
     */
    private List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance> balancedDiskPerformances;
    /**
     * @return Representation of disk performance detail parameters.
     * 
     */
    private List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance> highDiskPerformances;
    /**
     * @return Size in GBs.
     * 
     */
    private Integer sizeInGbs;

    private GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList() {}
    /**
     * @return Representation of disk performance detail parameters.
     * 
     */
    public List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance> balancedDiskPerformances() {
        return this.balancedDiskPerformances;
    }
    /**
     * @return Representation of disk performance detail parameters.
     * 
     */
    public List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance> highDiskPerformances() {
        return this.highDiskPerformances;
    }
    /**
     * @return Size in GBs.
     * 
     */
    public Integer sizeInGbs() {
        return this.sizeInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance> balancedDiskPerformances;
        private List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance> highDiskPerformances;
        private Integer sizeInGbs;
        public Builder() {}
        public Builder(GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.balancedDiskPerformances = defaults.balancedDiskPerformances;
    	      this.highDiskPerformances = defaults.highDiskPerformances;
    	      this.sizeInGbs = defaults.sizeInGbs;
        }

        @CustomType.Setter
        public Builder balancedDiskPerformances(List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance> balancedDiskPerformances) {
            this.balancedDiskPerformances = Objects.requireNonNull(balancedDiskPerformances);
            return this;
        }
        public Builder balancedDiskPerformances(GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListBalancedDiskPerformance... balancedDiskPerformances) {
            return balancedDiskPerformances(List.of(balancedDiskPerformances));
        }
        @CustomType.Setter
        public Builder highDiskPerformances(List<GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance> highDiskPerformances) {
            this.highDiskPerformances = Objects.requireNonNull(highDiskPerformances);
            return this;
        }
        public Builder highDiskPerformances(GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceListHighDiskPerformance... highDiskPerformances) {
            return highDiskPerformances(List.of(highDiskPerformances));
        }
        @CustomType.Setter
        public Builder sizeInGbs(Integer sizeInGbs) {
            this.sizeInGbs = Objects.requireNonNull(sizeInGbs);
            return this;
        }
        public GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList build() {
            final var o = new GetDbSystemStoragePerformancesDbSystemStoragePerformanceRecoStoragePerformanceList();
            o.balancedDiskPerformances = balancedDiskPerformances;
            o.highDiskPerformances = highDiskPerformances;
            o.sizeInGbs = sizeInGbs;
            return o;
        }
    }
}