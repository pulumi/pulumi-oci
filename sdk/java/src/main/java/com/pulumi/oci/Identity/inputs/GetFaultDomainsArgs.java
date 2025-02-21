// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.GetFaultDomainsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFaultDomainsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFaultDomainsArgs Empty = new GetFaultDomainsArgs();

    /**
     * The name of the availibilityDomain.
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The name of the availibilityDomain.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetFaultDomainsFilterArgs>> filters;

    public Optional<Output<List<GetFaultDomainsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetFaultDomainsArgs() {}

    private GetFaultDomainsArgs(GetFaultDomainsArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFaultDomainsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFaultDomainsArgs $;

        public Builder() {
            $ = new GetFaultDomainsArgs();
        }

        public Builder(GetFaultDomainsArgs defaults) {
            $ = new GetFaultDomainsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availibilityDomain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The name of the availibilityDomain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetFaultDomainsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetFaultDomainsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetFaultDomainsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetFaultDomainsArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("GetFaultDomainsArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetFaultDomainsArgs", "compartmentId");
            }
            return $;
        }
    }

}
