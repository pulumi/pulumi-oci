// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetIdpGroupMappingsFilter;
import com.pulumi.oci.Identity.outputs.GetIdpGroupMappingsIdpGroupMapping;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetIdpGroupMappingsResult {
    private @Nullable List<GetIdpGroupMappingsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the `IdentityProvider` this mapping belongs to.
     * 
     */
    private String identityProviderId;
    /**
     * @return The list of idp_group_mappings.
     * 
     */
    private List<GetIdpGroupMappingsIdpGroupMapping> idpGroupMappings;

    private GetIdpGroupMappingsResult() {}
    public List<GetIdpGroupMappingsFilter> filters() {
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
     * @return The OCID of the `IdentityProvider` this mapping belongs to.
     * 
     */
    public String identityProviderId() {
        return this.identityProviderId;
    }
    /**
     * @return The list of idp_group_mappings.
     * 
     */
    public List<GetIdpGroupMappingsIdpGroupMapping> idpGroupMappings() {
        return this.idpGroupMappings;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIdpGroupMappingsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetIdpGroupMappingsFilter> filters;
        private String id;
        private String identityProviderId;
        private List<GetIdpGroupMappingsIdpGroupMapping> idpGroupMappings;
        public Builder() {}
        public Builder(GetIdpGroupMappingsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.identityProviderId = defaults.identityProviderId;
    	      this.idpGroupMappings = defaults.idpGroupMappings;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetIdpGroupMappingsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIdpGroupMappingsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder identityProviderId(String identityProviderId) {
            this.identityProviderId = Objects.requireNonNull(identityProviderId);
            return this;
        }
        @CustomType.Setter
        public Builder idpGroupMappings(List<GetIdpGroupMappingsIdpGroupMapping> idpGroupMappings) {
            this.idpGroupMappings = Objects.requireNonNull(idpGroupMappings);
            return this;
        }
        public Builder idpGroupMappings(GetIdpGroupMappingsIdpGroupMapping... idpGroupMappings) {
            return idpGroupMappings(List.of(idpGroupMappings));
        }
        public GetIdpGroupMappingsResult build() {
            final var o = new GetIdpGroupMappingsResult();
            o.filters = filters;
            o.id = id;
            o.identityProviderId = identityProviderId;
            o.idpGroupMappings = idpGroupMappings;
            return o;
        }
    }
}