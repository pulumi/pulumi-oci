// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.GetShapesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetShapesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetShapesArgs Empty = new GetShapesArgs();

    /**
     * The name of the Availability Domain.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The name of the Availability Domain.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetShapesFilterArgs>> filters;

    public Optional<Output<List<GetShapesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Return shapes that are supported by the service feature.
     * 
     */
    @Import(name="isSupportedFors")
    private @Nullable Output<List<String>> isSupportedFors;

    /**
     * @return Return shapes that are supported by the service feature.
     * 
     */
    public Optional<Output<List<String>>> isSupportedFors() {
        return Optional.ofNullable(this.isSupportedFors);
    }

    /**
     * Name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetShapesArgs() {}

    private GetShapesArgs(GetShapesArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.isSupportedFors = $.isSupportedFors;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetShapesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetShapesArgs $;

        public Builder() {
            $ = new GetShapesArgs();
        }

        public Builder(GetShapesArgs defaults) {
            $ = new GetShapesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the Availability Domain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The name of the Availability Domain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetShapesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetShapesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetShapesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isSupportedFors Return shapes that are supported by the service feature.
         * 
         * @return builder
         * 
         */
        public Builder isSupportedFors(@Nullable Output<List<String>> isSupportedFors) {
            $.isSupportedFors = isSupportedFors;
            return this;
        }

        /**
         * @param isSupportedFors Return shapes that are supported by the service feature.
         * 
         * @return builder
         * 
         */
        public Builder isSupportedFors(List<String> isSupportedFors) {
            return isSupportedFors(Output.of(isSupportedFors));
        }

        /**
         * @param isSupportedFors Return shapes that are supported by the service feature.
         * 
         * @return builder
         * 
         */
        public Builder isSupportedFors(String... isSupportedFors) {
            return isSupportedFors(List.of(isSupportedFors));
        }

        /**
         * @param name Name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetShapesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}