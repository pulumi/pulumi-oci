// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.util.Objects;

@CustomType
public final class GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance {
    /**
     * @return Disk IOPS in thousands.
     * 
     */
    private Double diskIops;
    /**
     * @return Disk Throughput in Mbps.
     * 
     */
    private Double diskThroughputInMbps;

    private GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance() {}
    /**
     * @return Disk IOPS in thousands.
     * 
     */
    public Double diskIops() {
        return this.diskIops;
    }
    /**
     * @return Disk Throughput in Mbps.
     * 
     */
    public Double diskThroughputInMbps() {
        return this.diskThroughputInMbps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double diskIops;
        private Double diskThroughputInMbps;
        public Builder() {}
        public Builder(GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.diskIops = defaults.diskIops;
    	      this.diskThroughputInMbps = defaults.diskThroughputInMbps;
        }

        @CustomType.Setter
        public Builder diskIops(Double diskIops) {
            if (diskIops == null) {
              throw new MissingRequiredPropertyException("GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance", "diskIops");
            }
            this.diskIops = diskIops;
            return this;
        }
        @CustomType.Setter
        public Builder diskThroughputInMbps(Double diskThroughputInMbps) {
            if (diskThroughputInMbps == null) {
              throw new MissingRequiredPropertyException("GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance", "diskThroughputInMbps");
            }
            this.diskThroughputInMbps = diskThroughputInMbps;
            return this;
        }
        public GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance build() {
            final var _resultValue = new GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformance();
            _resultValue.diskIops = diskIops;
            _resultValue.diskThroughputInMbps = diskThroughputInMbps;
            return _resultValue;
        }
    }
}
