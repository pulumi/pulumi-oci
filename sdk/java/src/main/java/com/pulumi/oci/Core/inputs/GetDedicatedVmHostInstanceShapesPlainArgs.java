// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetDedicatedVmHostInstanceShapesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDedicatedVmHostInstanceShapesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDedicatedVmHostInstanceShapesPlainArgs Empty = new GetDedicatedVmHostInstanceShapesPlainArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Dedicated VM host shape name
     * 
     */
    @Import(name="dedicatedVmHostShape")
    private @Nullable String dedicatedVmHostShape;

    /**
     * @return Dedicated VM host shape name
     * 
     */
    public Optional<String> dedicatedVmHostShape() {
        return Optional.ofNullable(this.dedicatedVmHostShape);
    }

    @Import(name="filters")
    private @Nullable List<GetDedicatedVmHostInstanceShapesFilter> filters;

    public Optional<List<GetDedicatedVmHostInstanceShapesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDedicatedVmHostInstanceShapesPlainArgs() {}

    private GetDedicatedVmHostInstanceShapesPlainArgs(GetDedicatedVmHostInstanceShapesPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.dedicatedVmHostShape = $.dedicatedVmHostShape;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDedicatedVmHostInstanceShapesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDedicatedVmHostInstanceShapesPlainArgs $;

        public Builder() {
            $ = new GetDedicatedVmHostInstanceShapesPlainArgs();
        }

        public Builder(GetDedicatedVmHostInstanceShapesPlainArgs defaults) {
            $ = new GetDedicatedVmHostInstanceShapesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param dedicatedVmHostShape Dedicated VM host shape name
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostShape(@Nullable String dedicatedVmHostShape) {
            $.dedicatedVmHostShape = dedicatedVmHostShape;
            return this;
        }

        public Builder filters(@Nullable List<GetDedicatedVmHostInstanceShapesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDedicatedVmHostInstanceShapesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetDedicatedVmHostInstanceShapesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}