// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetFaultDomainsFaultDomain;
import com.pulumi.oci.Identity.outputs.GetFaultDomainsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetFaultDomainsResult {
    /**
     * @return The name of the availabilityDomain where the Fault Domain belongs.
     * 
     */
    private String availabilityDomain;
    /**
     * @return The OCID of the compartment. Currently only tenancy (root) compartment can be provided.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of fault_domains.
     * 
     */
    private List<GetFaultDomainsFaultDomain> faultDomains;
    private @Nullable List<GetFaultDomainsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetFaultDomainsResult() {}
    /**
     * @return The name of the availabilityDomain where the Fault Domain belongs.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The OCID of the compartment. Currently only tenancy (root) compartment can be provided.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of fault_domains.
     * 
     */
    public List<GetFaultDomainsFaultDomain> faultDomains() {
        return this.faultDomains;
    }
    public List<GetFaultDomainsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFaultDomainsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private List<GetFaultDomainsFaultDomain> faultDomains;
        private @Nullable List<GetFaultDomainsFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetFaultDomainsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.faultDomains = defaults.faultDomains;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder faultDomains(List<GetFaultDomainsFaultDomain> faultDomains) {
            this.faultDomains = Objects.requireNonNull(faultDomains);
            return this;
        }
        public Builder faultDomains(GetFaultDomainsFaultDomain... faultDomains) {
            return faultDomains(List.of(faultDomains));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFaultDomainsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFaultDomainsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetFaultDomainsResult build() {
            final var o = new GetFaultDomainsResult();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.faultDomains = faultDomains;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}