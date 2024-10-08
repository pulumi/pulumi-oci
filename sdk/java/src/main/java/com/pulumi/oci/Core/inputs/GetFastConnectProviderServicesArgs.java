// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetFastConnectProviderServicesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFastConnectProviderServicesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFastConnectProviderServicesArgs Empty = new GetFastConnectProviderServicesArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetFastConnectProviderServicesFilterArgs>> filters;

    public Optional<Output<List<GetFastConnectProviderServicesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetFastConnectProviderServicesArgs() {}

    private GetFastConnectProviderServicesArgs(GetFastConnectProviderServicesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFastConnectProviderServicesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFastConnectProviderServicesArgs $;

        public Builder() {
            $ = new GetFastConnectProviderServicesArgs();
        }

        public Builder(GetFastConnectProviderServicesArgs defaults) {
            $ = new GetFastConnectProviderServicesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetFastConnectProviderServicesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetFastConnectProviderServicesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetFastConnectProviderServicesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetFastConnectProviderServicesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetFastConnectProviderServicesArgs", "compartmentId");
            }
            return $;
        }
    }

}
