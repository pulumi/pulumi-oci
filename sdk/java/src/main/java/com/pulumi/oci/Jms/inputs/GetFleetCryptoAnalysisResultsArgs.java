// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.inputs.GetFleetCryptoAnalysisResultsFilterArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFleetCryptoAnalysisResultsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetCryptoAnalysisResultsArgs Empty = new GetFleetCryptoAnalysisResultsArgs();

    /**
     * The aggregation mode of the crypto event analysis result.
     * 
     */
    @Import(name="aggregationMode")
    private @Nullable Output<String> aggregationMode;

    /**
     * @return The aggregation mode of the crypto event analysis result.
     * 
     */
    public Optional<Output<String>> aggregationMode() {
        return Optional.ofNullable(this.aggregationMode);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetFleetCryptoAnalysisResultsFilterArgs>> filters;

    public Optional<Output<List<GetFleetCryptoAnalysisResultsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * FindingCount of CryptoAnalysis Report.
     * 
     */
    @Import(name="findingCount")
    private @Nullable Output<Integer> findingCount;

    /**
     * @return FindingCount of CryptoAnalysis Report.
     * 
     */
    public Optional<Output<Integer>> findingCount() {
        return Optional.ofNullable(this.findingCount);
    }

    /**
     * FindingCount of CryptoAnalysis Report.
     * 
     */
    @Import(name="findingCountGreaterThan")
    private @Nullable Output<Integer> findingCountGreaterThan;

    /**
     * @return FindingCount of CryptoAnalysis Report.
     * 
     */
    public Optional<Output<Integer>> findingCountGreaterThan() {
        return Optional.ofNullable(this.findingCountGreaterThan);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    @Import(name="fleetId", required=true)
    private Output<String> fleetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    public Output<String> fleetId() {
        return this.fleetId;
    }

    /**
     * The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    @Import(name="hostName")
    private @Nullable Output<String> hostName;

    /**
     * @return The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    public Optional<Output<String>> hostName() {
        return Optional.ofNullable(this.hostName);
    }

    /**
     * The Fleet-unique identifier of the related managed instance.
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable Output<String> managedInstanceId;

    /**
     * @return The Fleet-unique identifier of the related managed instance.
     * 
     */
    public Optional<Output<String>> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * Non Compliant Finding Count of CryptoAnalysis Report.
     * 
     */
    @Import(name="nonCompliantFindingCount")
    private @Nullable Output<Integer> nonCompliantFindingCount;

    /**
     * @return Non Compliant Finding Count of CryptoAnalysis Report.
     * 
     */
    public Optional<Output<Integer>> nonCompliantFindingCount() {
        return Optional.ofNullable(this.nonCompliantFindingCount);
    }

    /**
     * Non Compliant Finding Count of CryptoAnalysis Report.
     * 
     */
    @Import(name="nonCompliantFindingCountGreaterThan")
    private @Nullable Output<Integer> nonCompliantFindingCountGreaterThan;

    /**
     * @return Non Compliant Finding Count of CryptoAnalysis Report.
     * 
     */
    public Optional<Output<Integer>> nonCompliantFindingCountGreaterThan() {
        return Optional.ofNullable(this.nonCompliantFindingCountGreaterThan);
    }

    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeEnd")
    private @Nullable Output<String> timeEnd;

    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<Output<String>> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }

    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeStart")
    private @Nullable Output<String> timeStart;

    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<Output<String>> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    private GetFleetCryptoAnalysisResultsArgs() {}

    private GetFleetCryptoAnalysisResultsArgs(GetFleetCryptoAnalysisResultsArgs $) {
        this.aggregationMode = $.aggregationMode;
        this.filters = $.filters;
        this.findingCount = $.findingCount;
        this.findingCountGreaterThan = $.findingCountGreaterThan;
        this.fleetId = $.fleetId;
        this.hostName = $.hostName;
        this.managedInstanceId = $.managedInstanceId;
        this.nonCompliantFindingCount = $.nonCompliantFindingCount;
        this.nonCompliantFindingCountGreaterThan = $.nonCompliantFindingCountGreaterThan;
        this.timeEnd = $.timeEnd;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetCryptoAnalysisResultsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetCryptoAnalysisResultsArgs $;

        public Builder() {
            $ = new GetFleetCryptoAnalysisResultsArgs();
        }

        public Builder(GetFleetCryptoAnalysisResultsArgs defaults) {
            $ = new GetFleetCryptoAnalysisResultsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param aggregationMode The aggregation mode of the crypto event analysis result.
         * 
         * @return builder
         * 
         */
        public Builder aggregationMode(@Nullable Output<String> aggregationMode) {
            $.aggregationMode = aggregationMode;
            return this;
        }

        /**
         * @param aggregationMode The aggregation mode of the crypto event analysis result.
         * 
         * @return builder
         * 
         */
        public Builder aggregationMode(String aggregationMode) {
            return aggregationMode(Output.of(aggregationMode));
        }

        public Builder filters(@Nullable Output<List<GetFleetCryptoAnalysisResultsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetFleetCryptoAnalysisResultsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetFleetCryptoAnalysisResultsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param findingCount FindingCount of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder findingCount(@Nullable Output<Integer> findingCount) {
            $.findingCount = findingCount;
            return this;
        }

        /**
         * @param findingCount FindingCount of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder findingCount(Integer findingCount) {
            return findingCount(Output.of(findingCount));
        }

        /**
         * @param findingCountGreaterThan FindingCount of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder findingCountGreaterThan(@Nullable Output<Integer> findingCountGreaterThan) {
            $.findingCountGreaterThan = findingCountGreaterThan;
            return this;
        }

        /**
         * @param findingCountGreaterThan FindingCount of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder findingCountGreaterThan(Integer findingCountGreaterThan) {
            return findingCountGreaterThan(Output.of(findingCountGreaterThan));
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(Output<String> fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            return fleetId(Output.of(fleetId));
        }

        /**
         * @param hostName The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder hostName(@Nullable Output<String> hostName) {
            $.hostName = hostName;
            return this;
        }

        /**
         * @param hostName The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder hostName(String hostName) {
            return hostName(Output.of(hostName));
        }

        /**
         * @param managedInstanceId The Fleet-unique identifier of the related managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable Output<String> managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param managedInstanceId The Fleet-unique identifier of the related managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            return managedInstanceId(Output.of(managedInstanceId));
        }

        /**
         * @param nonCompliantFindingCount Non Compliant Finding Count of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder nonCompliantFindingCount(@Nullable Output<Integer> nonCompliantFindingCount) {
            $.nonCompliantFindingCount = nonCompliantFindingCount;
            return this;
        }

        /**
         * @param nonCompliantFindingCount Non Compliant Finding Count of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder nonCompliantFindingCount(Integer nonCompliantFindingCount) {
            return nonCompliantFindingCount(Output.of(nonCompliantFindingCount));
        }

        /**
         * @param nonCompliantFindingCountGreaterThan Non Compliant Finding Count of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder nonCompliantFindingCountGreaterThan(@Nullable Output<Integer> nonCompliantFindingCountGreaterThan) {
            $.nonCompliantFindingCountGreaterThan = nonCompliantFindingCountGreaterThan;
            return this;
        }

        /**
         * @param nonCompliantFindingCountGreaterThan Non Compliant Finding Count of CryptoAnalysis Report.
         * 
         * @return builder
         * 
         */
        public Builder nonCompliantFindingCountGreaterThan(Integer nonCompliantFindingCountGreaterThan) {
            return nonCompliantFindingCountGreaterThan(Output.of(nonCompliantFindingCountGreaterThan));
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(@Nullable Output<String> timeEnd) {
            $.timeEnd = timeEnd;
            return this;
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(String timeEnd) {
            return timeEnd(Output.of(timeEnd));
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable Output<String> timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(String timeStart) {
            return timeStart(Output.of(timeStart));
        }

        public GetFleetCryptoAnalysisResultsArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetCryptoAnalysisResultsArgs", "fleetId");
            }
            return $;
        }
    }

}
