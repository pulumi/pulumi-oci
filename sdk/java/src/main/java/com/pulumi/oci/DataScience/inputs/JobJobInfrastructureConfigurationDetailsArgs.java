// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.JobJobInfrastructureConfigurationDetailsJobShapeConfigDetailsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JobJobInfrastructureConfigurationDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final JobJobInfrastructureConfigurationDetailsArgs Empty = new JobJobInfrastructureConfigurationDetailsArgs();

    /**
     * (Updatable) The size of the block storage volume to attach to the instance running the job
     * 
     */
    @Import(name="blockStorageSizeInGbs", required=true)
    private Output<Integer> blockStorageSizeInGbs;

    /**
     * @return (Updatable) The size of the block storage volume to attach to the instance running the job
     * 
     */
    public Output<Integer> blockStorageSizeInGbs() {
        return this.blockStorageSizeInGbs;
    }

    /**
     * (Updatable) The infrastructure type used for job run.
     * 
     */
    @Import(name="jobInfrastructureType", required=true)
    private Output<String> jobInfrastructureType;

    /**
     * @return (Updatable) The infrastructure type used for job run.
     * 
     */
    public Output<String> jobInfrastructureType() {
        return this.jobInfrastructureType;
    }

    /**
     * (Updatable) Details for the job run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    @Import(name="jobShapeConfigDetails")
    private @Nullable Output<JobJobInfrastructureConfigurationDetailsJobShapeConfigDetailsArgs> jobShapeConfigDetails;

    /**
     * @return (Updatable) Details for the job run shape configuration. Specify only when a flex shape is selected.
     * 
     */
    public Optional<Output<JobJobInfrastructureConfigurationDetailsJobShapeConfigDetailsArgs>> jobShapeConfigDetails() {
        return Optional.ofNullable(this.jobShapeConfigDetails);
    }

    /**
     * (Updatable) The shape used to launch the job run instances.
     * 
     */
    @Import(name="shapeName", required=true)
    private Output<String> shapeName;

    /**
     * @return (Updatable) The shape used to launch the job run instances.
     * 
     */
    public Output<String> shapeName() {
        return this.shapeName;
    }

    /**
     * (Updatable) The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return (Updatable) The subnet to create a secondary vnic in to attach to the instance running the job
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    private JobJobInfrastructureConfigurationDetailsArgs() {}

    private JobJobInfrastructureConfigurationDetailsArgs(JobJobInfrastructureConfigurationDetailsArgs $) {
        this.blockStorageSizeInGbs = $.blockStorageSizeInGbs;
        this.jobInfrastructureType = $.jobInfrastructureType;
        this.jobShapeConfigDetails = $.jobShapeConfigDetails;
        this.shapeName = $.shapeName;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JobJobInfrastructureConfigurationDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JobJobInfrastructureConfigurationDetailsArgs $;

        public Builder() {
            $ = new JobJobInfrastructureConfigurationDetailsArgs();
        }

        public Builder(JobJobInfrastructureConfigurationDetailsArgs defaults) {
            $ = new JobJobInfrastructureConfigurationDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockStorageSizeInGbs (Updatable) The size of the block storage volume to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(Output<Integer> blockStorageSizeInGbs) {
            $.blockStorageSizeInGbs = blockStorageSizeInGbs;
            return this;
        }

        /**
         * @param blockStorageSizeInGbs (Updatable) The size of the block storage volume to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(Integer blockStorageSizeInGbs) {
            return blockStorageSizeInGbs(Output.of(blockStorageSizeInGbs));
        }

        /**
         * @param jobInfrastructureType (Updatable) The infrastructure type used for job run.
         * 
         * @return builder
         * 
         */
        public Builder jobInfrastructureType(Output<String> jobInfrastructureType) {
            $.jobInfrastructureType = jobInfrastructureType;
            return this;
        }

        /**
         * @param jobInfrastructureType (Updatable) The infrastructure type used for job run.
         * 
         * @return builder
         * 
         */
        public Builder jobInfrastructureType(String jobInfrastructureType) {
            return jobInfrastructureType(Output.of(jobInfrastructureType));
        }

        /**
         * @param jobShapeConfigDetails (Updatable) Details for the job run shape configuration. Specify only when a flex shape is selected.
         * 
         * @return builder
         * 
         */
        public Builder jobShapeConfigDetails(@Nullable Output<JobJobInfrastructureConfigurationDetailsJobShapeConfigDetailsArgs> jobShapeConfigDetails) {
            $.jobShapeConfigDetails = jobShapeConfigDetails;
            return this;
        }

        /**
         * @param jobShapeConfigDetails (Updatable) Details for the job run shape configuration. Specify only when a flex shape is selected.
         * 
         * @return builder
         * 
         */
        public Builder jobShapeConfigDetails(JobJobInfrastructureConfigurationDetailsJobShapeConfigDetailsArgs jobShapeConfigDetails) {
            return jobShapeConfigDetails(Output.of(jobShapeConfigDetails));
        }

        /**
         * @param shapeName (Updatable) The shape used to launch the job run instances.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(Output<String> shapeName) {
            $.shapeName = shapeName;
            return this;
        }

        /**
         * @param shapeName (Updatable) The shape used to launch the job run instances.
         * 
         * @return builder
         * 
         */
        public Builder shapeName(String shapeName) {
            return shapeName(Output.of(shapeName));
        }

        /**
         * @param subnetId (Updatable) The subnet to create a secondary vnic in to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId (Updatable) The subnet to create a secondary vnic in to attach to the instance running the job
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public JobJobInfrastructureConfigurationDetailsArgs build() {
            $.blockStorageSizeInGbs = Objects.requireNonNull($.blockStorageSizeInGbs, "expected parameter 'blockStorageSizeInGbs' to be non-null");
            $.jobInfrastructureType = Objects.requireNonNull($.jobInfrastructureType, "expected parameter 'jobInfrastructureType' to be non-null");
            $.shapeName = Objects.requireNonNull($.shapeName, "expected parameter 'shapeName' to be non-null");
            return $;
        }
    }

}