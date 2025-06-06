// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.inputs.GetFleetPerformanceTuningAnalysisResultsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFleetPerformanceTuningAnalysisResultsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetPerformanceTuningAnalysisResultsPlainArgs Empty = new GetFleetPerformanceTuningAnalysisResultsPlainArgs();

    /**
     * The Fleet-unique identifier of the related application.
     * 
     */
    @Import(name="applicationId")
    private @Nullable String applicationId;

    /**
     * @return The Fleet-unique identifier of the related application.
     * 
     */
    public Optional<String> applicationId() {
        return Optional.ofNullable(this.applicationId);
    }

    /**
     * The name of the application.
     * 
     */
    @Import(name="applicationName")
    private @Nullable String applicationName;

    /**
     * @return The name of the application.
     * 
     */
    public Optional<String> applicationName() {
        return Optional.ofNullable(this.applicationName);
    }

    @Import(name="filters")
    private @Nullable List<GetFleetPerformanceTuningAnalysisResultsFilter> filters;

    public Optional<List<GetFleetPerformanceTuningAnalysisResultsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    @Import(name="fleetId", required=true)
    private String fleetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }

    /**
     * The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    @Import(name="hostName")
    private @Nullable String hostName;

    /**
     * @return The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    public Optional<String> hostName() {
        return Optional.ofNullable(this.hostName);
    }

    /**
     * The Fleet-unique identifier of the related managed instance.
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable String managedInstanceId;

    /**
     * @return The Fleet-unique identifier of the related managed instance.
     * 
     */
    public Optional<String> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeEnd")
    private @Nullable String timeEnd;

    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<String> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }

    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeStart")
    private @Nullable String timeStart;

    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<String> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    private GetFleetPerformanceTuningAnalysisResultsPlainArgs() {}

    private GetFleetPerformanceTuningAnalysisResultsPlainArgs(GetFleetPerformanceTuningAnalysisResultsPlainArgs $) {
        this.applicationId = $.applicationId;
        this.applicationName = $.applicationName;
        this.filters = $.filters;
        this.fleetId = $.fleetId;
        this.hostName = $.hostName;
        this.managedInstanceId = $.managedInstanceId;
        this.timeEnd = $.timeEnd;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetPerformanceTuningAnalysisResultsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetPerformanceTuningAnalysisResultsPlainArgs $;

        public Builder() {
            $ = new GetFleetPerformanceTuningAnalysisResultsPlainArgs();
        }

        public Builder(GetFleetPerformanceTuningAnalysisResultsPlainArgs defaults) {
            $ = new GetFleetPerformanceTuningAnalysisResultsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationId The Fleet-unique identifier of the related application.
         * 
         * @return builder
         * 
         */
        public Builder applicationId(@Nullable String applicationId) {
            $.applicationId = applicationId;
            return this;
        }

        /**
         * @param applicationName The name of the application.
         * 
         * @return builder
         * 
         */
        public Builder applicationName(@Nullable String applicationName) {
            $.applicationName = applicationName;
            return this;
        }

        public Builder filters(@Nullable List<GetFleetPerformanceTuningAnalysisResultsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetFleetPerformanceTuningAnalysisResultsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param hostName The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder hostName(@Nullable String hostName) {
            $.hostName = hostName;
            return this;
        }

        /**
         * @param managedInstanceId The Fleet-unique identifier of the related managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable String managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(@Nullable String timeEnd) {
            $.timeEnd = timeEnd;
            return this;
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable String timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        public GetFleetPerformanceTuningAnalysisResultsPlainArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetPerformanceTuningAnalysisResultsPlainArgs", "fleetId");
            }
            return $;
        }
    }

}
