// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JobRunJobInfrastructureConfigurationDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final JobRunJobInfrastructureConfigurationDetailArgs Empty = new JobRunJobInfrastructureConfigurationDetailArgs();

    /**
     * The size of the block storage volume to attach to the instance running the job
     * 
     */
    @Import(name="blockStorageSizeInGbs")
    private @Nullable Output<Integer> blockStorageSizeInGbs;

    /**
     * @return The size of the block storage volume to attach to the instance running the job
     * 
     */
    public Optional<Output<Integer>> blockStorageSizeInGbs() {
        return Optional.ofNullable(this.blockStorageSizeInGbs);
    }

    /**
     * The infrastructure type used for job run.
     * 
     */
    @Import(name="jobInfrastructureType")
    private @Nullable Output<String> jobInfrastructureType;

    /**
     * @return The infrastructure type used for job run.
     * 
     */
    public Optional<Output<String>> jobInfrastructureType() {
        return Optional.ofNullable(this.jobInfrastructureType);
    }

    /**
     * Details for the job run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    @Import(name="jobShapeConfigDetails")
    private @Nullable Output<List<JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs>> jobShapeConfigDetails;

    /**
     * @return Details for the job run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    public Optional<Output<List<JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs>>> jobShapeConfigDetails() {
        return Optional.ofNullable(this.jobShapeConfigDetails);
    }

    /**
     * The shape used to launch the job run instances.
     * 
     */
    @Import(name="shapeName")
    private @Nullable Output<String> shapeName;

    /**
     * @return The shape used to launch the job run instances.
     * 
     */
    public Optional<Output<String>> shapeName() {
        return Optional.ofNullable(this.shapeName);
    }

    /**
     * The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    private JobRunJobInfrastructureConfigurationDetailArgs() {}

    private JobRunJobInfrastructureConfigurationDetailArgs(JobRunJobInfrastructureConfigurationDetailArgs $) {
        this.blockStorageSizeInGbs = $.blockStorageSizeInGbs;
        this.jobInfrastructureType = $.jobInfrastructureType;
        this.jobShapeConfigDetails = $.jobShapeConfigDetails;
        this.shapeName = $.shapeName;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JobRunJobInfrastructureConfigurationDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JobRunJobInfrastructureConfigurationDetailArgs $;

        public Builder() {
            $ = new JobRunJobInfrastructureConfigurationDetailArgs();
        }

        public Builder(JobRunJobInfrastructureConfigurationDetailArgs defaults) {
            $ = new JobRunJobInfrastructureConfigurationDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockStorageSizeInGbs The size of the block storage volume to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(@Nullable Output<Integer> blockStorageSizeInGbs) {
            $.blockStorageSizeInGbs = blockStorageSizeInGbs;
            return this;
        }

        /**
         * @param blockStorageSizeInGbs The size of the block storage volume to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(Integer blockStorageSizeInGbs) {
            return blockStorageSizeInGbs(Output.of(blockStorageSizeInGbs));
        }

        /**
         * @param jobInfrastructureType The infrastructure type used for job run.
         * 
         * @return builder
         * 
         */
        public Builder jobInfrastructureType(@Nullable Output<String> jobInfrastructureType) {
            $.jobInfrastructureType = jobInfrastructureType;
            return this;
        }

        /**
         * @param jobInfrastructureType The infrastructure type used for job run.
         * 
         * @return builder
         * 
         */
        public Builder jobInfrastructureType(String jobInfrastructureType) {
            return jobInfrastructureType(Output.of(jobInfrastructureType));
        }

        /**
         * @param jobShapeConfigDetails Details for the job run shape configuration. Specify only when a flex shape is selected.
         * 
         * @return builder
         * 
         */
        public Builder jobShapeConfigDetails(@Nullable Output<List<JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs>> jobShapeConfigDetails) {
            $.jobShapeConfigDetails = jobShapeConfigDetails;
            return this;
        }

        /**
         * @param jobShapeConfigDetails Details for the job run shape configuration. Specify only when a flex shape is selected.
         * 
         * @return builder
         * 
         */
        public Builder jobShapeConfigDetails(List<JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs> jobShapeConfigDetails) {
            return jobShapeConfigDetails(Output.of(jobShapeConfigDetails));
        }

        /**
         * @param jobShapeConfigDetails Details for the job run shape configuration. Specify only when a flex shape is selected.
         * 
         * @return builder
         * 
         */
        public Builder jobShapeConfigDetails(JobRunJobInfrastructureConfigurationDetailJobShapeConfigDetailArgs... jobShapeConfigDetails) {
            return jobShapeConfigDetails(List.of(jobShapeConfigDetails));
        }

        /**
         * @param shapeName The shape used to launch the job run instances.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(@Nullable Output<String> shapeName) {
            $.shapeName = shapeName;
            return this;
        }

        /**
         * @param shapeName The shape used to launch the job run instances.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(String shapeName) {
            return shapeName(Output.of(shapeName));
        }

        /**
         * @param subnetId The subnet to create a secondary vnic in to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The subnet to create a secondary vnic in to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public JobRunJobInfrastructureConfigurationDetailArgs build() {
            return $;
        }
    }

}
