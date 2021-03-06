// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class JobRunJobInfrastructureConfigurationDetail {
    /**
     * @return The size of the block storage volume to attach to the instance running the job
     * 
     */
    private final @Nullable Integer blockStorageSizeInGbs;
    /**
     * @return The infrastructure type used for job run.
     * 
     */
    private final @Nullable String jobInfrastructureType;
    /**
     * @return The shape used to launch the job run instances.
     * 
     */
    private final @Nullable String shapeName;
    /**
     * @return The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    private final @Nullable String subnetId;

    @CustomType.Constructor
    private JobRunJobInfrastructureConfigurationDetail(
        @CustomType.Parameter("blockStorageSizeInGbs") @Nullable Integer blockStorageSizeInGbs,
        @CustomType.Parameter("jobInfrastructureType") @Nullable String jobInfrastructureType,
        @CustomType.Parameter("shapeName") @Nullable String shapeName,
        @CustomType.Parameter("subnetId") @Nullable String subnetId) {
        this.blockStorageSizeInGbs = blockStorageSizeInGbs;
        this.jobInfrastructureType = jobInfrastructureType;
        this.shapeName = shapeName;
        this.subnetId = subnetId;
    }

    /**
     * @return The size of the block storage volume to attach to the instance running the job
     * 
     */
    public Optional<Integer> blockStorageSizeInGbs() {
        return Optional.ofNullable(this.blockStorageSizeInGbs);
    }
    /**
     * @return The infrastructure type used for job run.
     * 
     */
    public Optional<String> jobInfrastructureType() {
        return Optional.ofNullable(this.jobInfrastructureType);
    }
    /**
     * @return The shape used to launch the job run instances.
     * 
     */
    public Optional<String> shapeName() {
        return Optional.ofNullable(this.shapeName);
    }
    /**
     * @return The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    public Optional<String> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(JobRunJobInfrastructureConfigurationDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Integer blockStorageSizeInGbs;
        private @Nullable String jobInfrastructureType;
        private @Nullable String shapeName;
        private @Nullable String subnetId;

        public Builder() {
    	      // Empty
        }

        public Builder(JobRunJobInfrastructureConfigurationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockStorageSizeInGbs = defaults.blockStorageSizeInGbs;
    	      this.jobInfrastructureType = defaults.jobInfrastructureType;
    	      this.shapeName = defaults.shapeName;
    	      this.subnetId = defaults.subnetId;
        }

        public Builder blockStorageSizeInGbs(@Nullable Integer blockStorageSizeInGbs) {
            this.blockStorageSizeInGbs = blockStorageSizeInGbs;
            return this;
        }
        public Builder jobInfrastructureType(@Nullable String jobInfrastructureType) {
            this.jobInfrastructureType = jobInfrastructureType;
            return this;
        }
        public Builder shapeName(@Nullable String shapeName) {
            this.shapeName = shapeName;
            return this;
        }
        public Builder subnetId(@Nullable String subnetId) {
            this.subnetId = subnetId;
            return this;
        }        public JobRunJobInfrastructureConfigurationDetail build() {
            return new JobRunJobInfrastructureConfigurationDetail(blockStorageSizeInGbs, jobInfrastructureType, shapeName, subnetId);
        }
    }
}
