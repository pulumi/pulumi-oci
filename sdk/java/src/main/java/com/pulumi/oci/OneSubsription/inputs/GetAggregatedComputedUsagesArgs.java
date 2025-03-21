// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OneSubsription.inputs.GetAggregatedComputedUsagesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAggregatedComputedUsagesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAggregatedComputedUsagesArgs Empty = new GetAggregatedComputedUsagesArgs();

    /**
     * The OCID of the root compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the root compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAggregatedComputedUsagesFilterArgs>> filters;

    public Optional<Output<List<GetAggregatedComputedUsagesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
     * 
     */
    @Import(name="grouping")
    private @Nullable Output<String> grouping;

    /**
     * @return Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
     * 
     */
    public Optional<Output<String>> grouping() {
        return Optional.ofNullable(this.grouping);
    }

    /**
     * Product part number for subscribed service line, called parent product.
     * 
     */
    @Import(name="parentProduct")
    private @Nullable Output<String> parentProduct;

    /**
     * @return Product part number for subscribed service line, called parent product.
     * 
     */
    public Optional<Output<String>> parentProduct() {
        return Optional.ofNullable(this.parentProduct);
    }

    /**
     * Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     * 
     */
    @Import(name="subscriptionId", required=true)
    private Output<String> subscriptionId;

    /**
     * @return Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
     * 
     */
    public Output<String> subscriptionId() {
        return this.subscriptionId;
    }

    /**
     * Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     * 
     */
    @Import(name="timeFrom", required=true)
    private Output<String> timeFrom;

    /**
     * @return Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
     * 
     */
    public Output<String> timeFrom() {
        return this.timeFrom;
    }

    /**
     * Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     * 
     */
    @Import(name="timeTo", required=true)
    private Output<String> timeTo;

    /**
     * @return Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
     * 
     */
    public Output<String> timeTo() {
        return this.timeTo;
    }

    private GetAggregatedComputedUsagesArgs() {}

    private GetAggregatedComputedUsagesArgs(GetAggregatedComputedUsagesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.grouping = $.grouping;
        this.parentProduct = $.parentProduct;
        this.subscriptionId = $.subscriptionId;
        this.timeFrom = $.timeFrom;
        this.timeTo = $.timeTo;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAggregatedComputedUsagesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAggregatedComputedUsagesArgs $;

        public Builder() {
            $ = new GetAggregatedComputedUsagesArgs();
        }

        public Builder(GetAggregatedComputedUsagesArgs defaults) {
            $ = new GetAggregatedComputedUsagesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetAggregatedComputedUsagesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAggregatedComputedUsagesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAggregatedComputedUsagesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param grouping Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
         * 
         * @return builder
         * 
         */
        public Builder grouping(@Nullable Output<String> grouping) {
            $.grouping = grouping;
            return this;
        }

        /**
         * @param grouping Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
         * 
         * @return builder
         * 
         */
        public Builder grouping(String grouping) {
            return grouping(Output.of(grouping));
        }

        /**
         * @param parentProduct Product part number for subscribed service line, called parent product.
         * 
         * @return builder
         * 
         */
        public Builder parentProduct(@Nullable Output<String> parentProduct) {
            $.parentProduct = parentProduct;
            return this;
        }

        /**
         * @param parentProduct Product part number for subscribed service line, called parent product.
         * 
         * @return builder
         * 
         */
        public Builder parentProduct(String parentProduct) {
            return parentProduct(Output.of(parentProduct));
        }

        /**
         * @param subscriptionId Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(Output<String> subscriptionId) {
            $.subscriptionId = subscriptionId;
            return this;
        }

        /**
         * @param subscriptionId Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(String subscriptionId) {
            return subscriptionId(Output.of(subscriptionId));
        }

        /**
         * @param timeFrom Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeFrom(Output<String> timeFrom) {
            $.timeFrom = timeFrom;
            return this;
        }

        /**
         * @param timeFrom Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeFrom(String timeFrom) {
            return timeFrom(Output.of(timeFrom));
        }

        /**
         * @param timeTo Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeTo(Output<String> timeTo) {
            $.timeTo = timeTo;
            return this;
        }

        /**
         * @param timeTo Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
         * 
         * @return builder
         * 
         */
        public Builder timeTo(String timeTo) {
            return timeTo(Output.of(timeTo));
        }

        public GetAggregatedComputedUsagesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAggregatedComputedUsagesArgs", "compartmentId");
            }
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetAggregatedComputedUsagesArgs", "subscriptionId");
            }
            if ($.timeFrom == null) {
                throw new MissingRequiredPropertyException("GetAggregatedComputedUsagesArgs", "timeFrom");
            }
            if ($.timeTo == null) {
                throw new MissingRequiredPropertyException("GetAggregatedComputedUsagesArgs", "timeTo");
            }
            return $;
        }
    }

}
