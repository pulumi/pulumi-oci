// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.GetFaultDomainsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFaultDomainsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFaultDomainsPlainArgs Empty = new GetFaultDomainsPlainArgs();

    /**
     * The name of the availibilityDomain.
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private String availabilityDomain;

    /**
     * @return The name of the availibilityDomain.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetFaultDomainsFilter> filters;

    public Optional<List<GetFaultDomainsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetFaultDomainsPlainArgs() {}

    private GetFaultDomainsPlainArgs(GetFaultDomainsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFaultDomainsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFaultDomainsPlainArgs $;

        public Builder() {
            $ = new GetFaultDomainsPlainArgs();
        }

        public Builder(GetFaultDomainsPlainArgs defaults) {
            $ = new GetFaultDomainsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availibilityDomain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetFaultDomainsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetFaultDomainsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetFaultDomainsPlainArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("GetFaultDomainsPlainArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetFaultDomainsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
