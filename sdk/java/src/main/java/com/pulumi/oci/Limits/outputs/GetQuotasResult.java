// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Limits.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Limits.outputs.GetQuotasFilter;
import com.pulumi.oci.Limits.outputs.GetQuotasQuota;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetQuotasResult {
    /**
     * @return The OCID of the compartment containing the resource this quota applies to.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetQuotasFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     * 
     */
    private @Nullable String name;
    /**
     * @return The list of quotas.
     * 
     */
    private List<GetQuotasQuota> quotas;
    /**
     * @return The quota&#39;s current state.
     * 
     */
    private @Nullable String state;

    private GetQuotasResult() {}
    /**
     * @return The OCID of the compartment containing the resource this quota applies to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetQuotasFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The list of quotas.
     * 
     */
    public List<GetQuotasQuota> quotas() {
        return this.quotas;
    }
    /**
     * @return The quota&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetQuotasResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetQuotasFilter> filters;
        private String id;
        private @Nullable String name;
        private List<GetQuotasQuota> quotas;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetQuotasResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.quotas = defaults.quotas;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetQuotasFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetQuotasFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder quotas(List<GetQuotasQuota> quotas) {
            this.quotas = Objects.requireNonNull(quotas);
            return this;
        }
        public Builder quotas(GetQuotasQuota... quotas) {
            return quotas(List.of(quotas));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetQuotasResult build() {
            final var o = new GetQuotasResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.quotas = quotas;
            o.state = state;
            return o;
        }
    }
}