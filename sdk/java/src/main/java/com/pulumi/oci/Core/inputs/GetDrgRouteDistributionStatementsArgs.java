// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetDrgRouteDistributionStatementsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDrgRouteDistributionStatementsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrgRouteDistributionStatementsArgs Empty = new GetDrgRouteDistributionStatementsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
     * 
     */
    @Import(name="drgRouteDistributionId", required=true)
    private Output<String> drgRouteDistributionId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
     * 
     */
    public Output<String> drgRouteDistributionId() {
        return this.drgRouteDistributionId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDrgRouteDistributionStatementsFilterArgs>> filters;

    public Optional<Output<List<GetDrgRouteDistributionStatementsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDrgRouteDistributionStatementsArgs() {}

    private GetDrgRouteDistributionStatementsArgs(GetDrgRouteDistributionStatementsArgs $) {
        this.drgRouteDistributionId = $.drgRouteDistributionId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrgRouteDistributionStatementsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrgRouteDistributionStatementsArgs $;

        public Builder() {
            $ = new GetDrgRouteDistributionStatementsArgs();
        }

        public Builder(GetDrgRouteDistributionStatementsArgs defaults) {
            $ = new GetDrgRouteDistributionStatementsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param drgRouteDistributionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteDistributionId(Output<String> drgRouteDistributionId) {
            $.drgRouteDistributionId = drgRouteDistributionId;
            return this;
        }

        /**
         * @param drgRouteDistributionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteDistributionId(String drgRouteDistributionId) {
            return drgRouteDistributionId(Output.of(drgRouteDistributionId));
        }

        public Builder filters(@Nullable Output<List<GetDrgRouteDistributionStatementsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDrgRouteDistributionStatementsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDrgRouteDistributionStatementsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDrgRouteDistributionStatementsArgs build() {
            if ($.drgRouteDistributionId == null) {
                throw new MissingRequiredPropertyException("GetDrgRouteDistributionStatementsArgs", "drgRouteDistributionId");
            }
            return $;
        }
    }

}
