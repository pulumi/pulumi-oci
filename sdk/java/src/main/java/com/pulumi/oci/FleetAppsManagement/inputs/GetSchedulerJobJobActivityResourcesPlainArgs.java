// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.GetSchedulerJobJobActivityResourcesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSchedulerJobJobActivityResourcesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSchedulerJobJobActivityResourcesPlainArgs Empty = new GetSchedulerJobJobActivityResourcesPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetSchedulerJobJobActivityResourcesFilter> filters;

    public Optional<List<GetSchedulerJobJobActivityResourcesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * unique jobActivity identifier
     * 
     */
    @Import(name="jobActivityId", required=true)
    private String jobActivityId;

    /**
     * @return unique jobActivity identifier
     * 
     */
    public String jobActivityId() {
        return this.jobActivityId;
    }

    /**
     * Task Id
     * 
     */
    @Import(name="resourceTaskId")
    private @Nullable String resourceTaskId;

    /**
     * @return Task Id
     * 
     */
    public Optional<String> resourceTaskId() {
        return Optional.ofNullable(this.resourceTaskId);
    }

    /**
     * unique SchedulerJob identifier
     * 
     */
    @Import(name="schedulerJobId", required=true)
    private String schedulerJobId;

    /**
     * @return unique SchedulerJob identifier
     * 
     */
    public String schedulerJobId() {
        return this.schedulerJobId;
    }

    /**
     * Task Order Sequence
     * 
     */
    @Import(name="sequence")
    private @Nullable String sequence;

    /**
     * @return Task Order Sequence
     * 
     */
    public Optional<String> sequence() {
        return Optional.ofNullable(this.sequence);
    }

    /**
     * Unique step name
     * 
     */
    @Import(name="stepName")
    private @Nullable String stepName;

    /**
     * @return Unique step name
     * 
     */
    public Optional<String> stepName() {
        return Optional.ofNullable(this.stepName);
    }

    /**
     * Unique target name
     * 
     */
    @Import(name="targetName")
    private @Nullable String targetName;

    /**
     * @return Unique target name
     * 
     */
    public Optional<String> targetName() {
        return Optional.ofNullable(this.targetName);
    }

    private GetSchedulerJobJobActivityResourcesPlainArgs() {}

    private GetSchedulerJobJobActivityResourcesPlainArgs(GetSchedulerJobJobActivityResourcesPlainArgs $) {
        this.filters = $.filters;
        this.jobActivityId = $.jobActivityId;
        this.resourceTaskId = $.resourceTaskId;
        this.schedulerJobId = $.schedulerJobId;
        this.sequence = $.sequence;
        this.stepName = $.stepName;
        this.targetName = $.targetName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSchedulerJobJobActivityResourcesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSchedulerJobJobActivityResourcesPlainArgs $;

        public Builder() {
            $ = new GetSchedulerJobJobActivityResourcesPlainArgs();
        }

        public Builder(GetSchedulerJobJobActivityResourcesPlainArgs defaults) {
            $ = new GetSchedulerJobJobActivityResourcesPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetSchedulerJobJobActivityResourcesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSchedulerJobJobActivityResourcesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param jobActivityId unique jobActivity identifier
         * 
         * @return builder
         * 
         */
        public Builder jobActivityId(String jobActivityId) {
            $.jobActivityId = jobActivityId;
            return this;
        }

        /**
         * @param resourceTaskId Task Id
         * 
         * @return builder
         * 
         */
        public Builder resourceTaskId(@Nullable String resourceTaskId) {
            $.resourceTaskId = resourceTaskId;
            return this;
        }

        /**
         * @param schedulerJobId unique SchedulerJob identifier
         * 
         * @return builder
         * 
         */
        public Builder schedulerJobId(String schedulerJobId) {
            $.schedulerJobId = schedulerJobId;
            return this;
        }

        /**
         * @param sequence Task Order Sequence
         * 
         * @return builder
         * 
         */
        public Builder sequence(@Nullable String sequence) {
            $.sequence = sequence;
            return this;
        }

        /**
         * @param stepName Unique step name
         * 
         * @return builder
         * 
         */
        public Builder stepName(@Nullable String stepName) {
            $.stepName = stepName;
            return this;
        }

        /**
         * @param targetName Unique target name
         * 
         * @return builder
         * 
         */
        public Builder targetName(@Nullable String targetName) {
            $.targetName = targetName;
            return this;
        }

        public GetSchedulerJobJobActivityResourcesPlainArgs build() {
            if ($.jobActivityId == null) {
                throw new MissingRequiredPropertyException("GetSchedulerJobJobActivityResourcesPlainArgs", "jobActivityId");
            }
            if ($.schedulerJobId == null) {
                throw new MissingRequiredPropertyException("GetSchedulerJobJobActivityResourcesPlainArgs", "schedulerJobId");
            }
            return $;
        }
    }

}
