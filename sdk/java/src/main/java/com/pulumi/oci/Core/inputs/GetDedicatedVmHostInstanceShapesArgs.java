// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetDedicatedVmHostInstanceShapesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDedicatedVmHostInstanceShapesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDedicatedVmHostInstanceShapesArgs Empty = new GetDedicatedVmHostInstanceShapesArgs();

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
     * Dedicated VM host shape name
     * 
     */
    @Import(name="dedicatedVmHostShape")
    private @Nullable Output<String> dedicatedVmHostShape;

    /**
     * @return Dedicated VM host shape name
     * 
     */
    public Optional<Output<String>> dedicatedVmHostShape() {
        return Optional.ofNullable(this.dedicatedVmHostShape);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDedicatedVmHostInstanceShapesFilterArgs>> filters;

    public Optional<Output<List<GetDedicatedVmHostInstanceShapesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDedicatedVmHostInstanceShapesArgs() {}

    private GetDedicatedVmHostInstanceShapesArgs(GetDedicatedVmHostInstanceShapesArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.dedicatedVmHostShape = $.dedicatedVmHostShape;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDedicatedVmHostInstanceShapesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDedicatedVmHostInstanceShapesArgs $;

        public Builder() {
            $ = new GetDedicatedVmHostInstanceShapesArgs();
        }

        public Builder(GetDedicatedVmHostInstanceShapesArgs defaults) {
            $ = new GetDedicatedVmHostInstanceShapesArgs(Objects.requireNonNull(defaults));
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
         * @param dedicatedVmHostShape Dedicated VM host shape name
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostShape(@Nullable Output<String> dedicatedVmHostShape) {
            $.dedicatedVmHostShape = dedicatedVmHostShape;
            return this;
        }

        /**
         * @param dedicatedVmHostShape Dedicated VM host shape name
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostShape(String dedicatedVmHostShape) {
            return dedicatedVmHostShape(Output.of(dedicatedVmHostShape));
        }

        public Builder filters(@Nullable Output<List<GetDedicatedVmHostInstanceShapesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDedicatedVmHostInstanceShapesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDedicatedVmHostInstanceShapesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDedicatedVmHostInstanceShapesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}