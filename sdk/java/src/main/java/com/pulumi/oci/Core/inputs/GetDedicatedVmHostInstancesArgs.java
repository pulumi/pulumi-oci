// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetDedicatedVmHostInstancesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDedicatedVmHostInstancesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDedicatedVmHostInstancesArgs Empty = new GetDedicatedVmHostInstancesArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

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

    /**
     * The OCID of the dedicated VM host.
     * 
     */
    @Import(name="dedicatedVmHostId", required=true)
    private Output<String> dedicatedVmHostId;

    /**
     * @return The OCID of the dedicated VM host.
     * 
     */
    public Output<String> dedicatedVmHostId() {
        return this.dedicatedVmHostId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDedicatedVmHostInstancesFilterArgs>> filters;

    public Optional<Output<List<GetDedicatedVmHostInstancesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDedicatedVmHostInstancesArgs() {}

    private GetDedicatedVmHostInstancesArgs(GetDedicatedVmHostInstancesArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.dedicatedVmHostId = $.dedicatedVmHostId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDedicatedVmHostInstancesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDedicatedVmHostInstancesArgs $;

        public Builder() {
            $ = new GetDedicatedVmHostInstancesArgs();
        }

        public Builder(GetDedicatedVmHostInstancesArgs defaults) {
            $ = new GetDedicatedVmHostInstancesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
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

        /**
         * @param dedicatedVmHostId The OCID of the dedicated VM host.
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostId(Output<String> dedicatedVmHostId) {
            $.dedicatedVmHostId = dedicatedVmHostId;
            return this;
        }

        /**
         * @param dedicatedVmHostId The OCID of the dedicated VM host.
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostId(String dedicatedVmHostId) {
            return dedicatedVmHostId(Output.of(dedicatedVmHostId));
        }

        public Builder filters(@Nullable Output<List<GetDedicatedVmHostInstancesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDedicatedVmHostInstancesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDedicatedVmHostInstancesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDedicatedVmHostInstancesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDedicatedVmHostInstancesArgs", "compartmentId");
            }
            if ($.dedicatedVmHostId == null) {
                throw new MissingRequiredPropertyException("GetDedicatedVmHostInstancesArgs", "dedicatedVmHostId");
            }
            return $;
        }
    }

}
