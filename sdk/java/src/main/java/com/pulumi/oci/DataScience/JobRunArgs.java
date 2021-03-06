// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.JobRunJobConfigurationOverrideDetailsArgs;
import com.pulumi.oci.DataScience.inputs.JobRunJobLogConfigurationOverrideDetailsArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JobRunArgs extends com.pulumi.resources.ResourceArgs {

    public static final JobRunArgs Empty = new JobRunArgs();

    /**
     * If set to true, do not wait for the JobRun to reach completion prior to returning. Can be useful for JobRuns with a long duration.
     * 
     */
    @Import(name="asynchronous")
    private @Nullable Output<Boolean> asynchronous;

    /**
     * @return If set to true, do not wait for the JobRun to reach completion prior to returning. Can be useful for JobRuns with a long duration.
     * 
     */
    public Optional<Output<Boolean>> asynchronous() {
        return Optional.ofNullable(this.asynchronous);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly display name for the resource.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The job configuration details
     * 
     */
    @Import(name="jobConfigurationOverrideDetails")
    private @Nullable Output<JobRunJobConfigurationOverrideDetailsArgs> jobConfigurationOverrideDetails;

    /**
     * @return The job configuration details
     * 
     */
    public Optional<Output<JobRunJobConfigurationOverrideDetailsArgs>> jobConfigurationOverrideDetails() {
        return Optional.ofNullable(this.jobConfigurationOverrideDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job to create a run for.
     * 
     */
    @Import(name="jobId", required=true)
    private Output<String> jobId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job to create a run for.
     * 
     */
    public Output<String> jobId() {
        return this.jobId;
    }

    /**
     * Logging configuration for resource.
     * 
     */
    @Import(name="jobLogConfigurationOverrideDetails")
    private @Nullable Output<JobRunJobLogConfigurationOverrideDetailsArgs> jobLogConfigurationOverrideDetails;

    /**
     * @return Logging configuration for resource.
     * 
     */
    public Optional<Output<JobRunJobLogConfigurationOverrideDetailsArgs>> jobLogConfigurationOverrideDetails() {
        return Optional.ofNullable(this.jobLogConfigurationOverrideDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
     * 
     */
    @Import(name="projectId", required=true)
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }

    private JobRunArgs() {}

    private JobRunArgs(JobRunArgs $) {
        this.asynchronous = $.asynchronous;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.jobConfigurationOverrideDetails = $.jobConfigurationOverrideDetails;
        this.jobId = $.jobId;
        this.jobLogConfigurationOverrideDetails = $.jobLogConfigurationOverrideDetails;
        this.projectId = $.projectId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JobRunArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JobRunArgs $;

        public Builder() {
            $ = new JobRunArgs();
        }

        public Builder(JobRunArgs defaults) {
            $ = new JobRunArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param asynchronous If set to true, do not wait for the JobRun to reach completion prior to returning. Can be useful for JobRuns with a long duration.
         * 
         * @return builder
         * 
         */
        public Builder asynchronous(@Nullable Output<Boolean> asynchronous) {
            $.asynchronous = asynchronous;
            return this;
        }

        /**
         * @param asynchronous If set to true, do not wait for the JobRun to reach completion prior to returning. Can be useful for JobRuns with a long duration.
         * 
         * @return builder
         * 
         */
        public Builder asynchronous(Boolean asynchronous) {
            return asynchronous(Output.of(asynchronous));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param jobConfigurationOverrideDetails The job configuration details
         * 
         * @return builder
         * 
         */
        public Builder jobConfigurationOverrideDetails(@Nullable Output<JobRunJobConfigurationOverrideDetailsArgs> jobConfigurationOverrideDetails) {
            $.jobConfigurationOverrideDetails = jobConfigurationOverrideDetails;
            return this;
        }

        /**
         * @param jobConfigurationOverrideDetails The job configuration details
         * 
         * @return builder
         * 
         */
        public Builder jobConfigurationOverrideDetails(JobRunJobConfigurationOverrideDetailsArgs jobConfigurationOverrideDetails) {
            return jobConfigurationOverrideDetails(Output.of(jobConfigurationOverrideDetails));
        }

        /**
         * @param jobId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job to create a run for.
         * 
         * @return builder
         * 
         */
        public Builder jobId(Output<String> jobId) {
            $.jobId = jobId;
            return this;
        }

        /**
         * @param jobId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job to create a run for.
         * 
         * @return builder
         * 
         */
        public Builder jobId(String jobId) {
            return jobId(Output.of(jobId));
        }

        /**
         * @param jobLogConfigurationOverrideDetails Logging configuration for resource.
         * 
         * @return builder
         * 
         */
        public Builder jobLogConfigurationOverrideDetails(@Nullable Output<JobRunJobLogConfigurationOverrideDetailsArgs> jobLogConfigurationOverrideDetails) {
            $.jobLogConfigurationOverrideDetails = jobLogConfigurationOverrideDetails;
            return this;
        }

        /**
         * @param jobLogConfigurationOverrideDetails Logging configuration for resource.
         * 
         * @return builder
         * 
         */
        public Builder jobLogConfigurationOverrideDetails(JobRunJobLogConfigurationOverrideDetailsArgs jobLogConfigurationOverrideDetails) {
            return jobLogConfigurationOverrideDetails(Output.of(jobLogConfigurationOverrideDetails));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        public JobRunArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.jobId = Objects.requireNonNull($.jobId, "expected parameter 'jobId' to be non-null");
            $.projectId = Objects.requireNonNull($.projectId, "expected parameter 'projectId' to be non-null");
            return $;
        }
    }

}
