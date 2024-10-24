// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetIdentityProviderGroupsFilter;
import com.pulumi.oci.Identity.outputs.GetIdentityProviderGroupsIdentityProviderGroup;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIdentityProviderGroupsResult {
    private @Nullable List<GetIdentityProviderGroupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of identity_provider_groups.
     * 
     */
    private List<GetIdentityProviderGroupsIdentityProviderGroup> identityProviderGroups;
    /**
     * @return The OCID of the `IdentityProvider` this group belongs to.
     * 
     */
    private String identityProviderId;
    /**
     * @return Display name of the group
     * 
     */
    private @Nullable String name;
    private @Nullable String state;

    private GetIdentityProviderGroupsResult() {}
    public List<GetIdentityProviderGroupsFilter> filters() {
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
     * @return The list of identity_provider_groups.
     * 
     */
    public List<GetIdentityProviderGroupsIdentityProviderGroup> identityProviderGroups() {
        return this.identityProviderGroups;
    }
    /**
     * @return The OCID of the `IdentityProvider` this group belongs to.
     * 
     */
    public String identityProviderId() {
        return this.identityProviderId;
    }
    /**
     * @return Display name of the group
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIdentityProviderGroupsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetIdentityProviderGroupsFilter> filters;
        private String id;
        private List<GetIdentityProviderGroupsIdentityProviderGroup> identityProviderGroups;
        private String identityProviderId;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetIdentityProviderGroupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.identityProviderGroups = defaults.identityProviderGroups;
    	      this.identityProviderId = defaults.identityProviderId;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetIdentityProviderGroupsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetIdentityProviderGroupsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identityProviderGroups(List<GetIdentityProviderGroupsIdentityProviderGroup> identityProviderGroups) {
            if (identityProviderGroups == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsResult", "identityProviderGroups");
            }
            this.identityProviderGroups = identityProviderGroups;
            return this;
        }
        public Builder identityProviderGroups(GetIdentityProviderGroupsIdentityProviderGroup... identityProviderGroups) {
            return identityProviderGroups(List.of(identityProviderGroups));
        }
        @CustomType.Setter
        public Builder identityProviderId(String identityProviderId) {
            if (identityProviderId == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsResult", "identityProviderId");
            }
            this.identityProviderId = identityProviderId;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetIdentityProviderGroupsResult build() {
            final var _resultValue = new GetIdentityProviderGroupsResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.identityProviderGroups = identityProviderGroups;
            _resultValue.identityProviderId = identityProviderId;
            _resultValue.name = name;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
