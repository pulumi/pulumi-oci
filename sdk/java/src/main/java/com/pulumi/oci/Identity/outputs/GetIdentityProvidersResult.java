// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetIdentityProvidersFilter;
import com.pulumi.oci.Identity.outputs.GetIdentityProvidersIdentityProvider;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIdentityProvidersResult {
    /**
     * @return The OCID of the tenancy containing the `IdentityProvider`.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetIdentityProvidersFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of identity_providers.
     * 
     */
    private List<GetIdentityProvidersIdentityProvider> identityProviders;
    /**
     * @return The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed. This is the name federated users see when choosing which identity provider to use when signing in to the Oracle Cloud Infrastructure Console.
     * 
     */
    private @Nullable String name;
    /**
     * @return The protocol used for federation. Allowed value: `SAML2`.  Example: `SAML2`
     * 
     */
    private String protocol;
    /**
     * @return The current state.
     * 
     */
    private @Nullable String state;

    private GetIdentityProvidersResult() {}
    /**
     * @return The OCID of the tenancy containing the `IdentityProvider`.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetIdentityProvidersFilter> filters() {
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
     * @return The list of identity_providers.
     * 
     */
    public List<GetIdentityProvidersIdentityProvider> identityProviders() {
        return this.identityProviders;
    }
    /**
     * @return The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed. This is the name federated users see when choosing which identity provider to use when signing in to the Oracle Cloud Infrastructure Console.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The protocol used for federation. Allowed value: `SAML2`.  Example: `SAML2`
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return The current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIdentityProvidersResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetIdentityProvidersFilter> filters;
        private String id;
        private List<GetIdentityProvidersIdentityProvider> identityProviders;
        private @Nullable String name;
        private String protocol;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetIdentityProvidersResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.identityProviders = defaults.identityProviders;
    	      this.name = defaults.name;
    	      this.protocol = defaults.protocol;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetIdentityProvidersFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetIdentityProvidersFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identityProviders(List<GetIdentityProvidersIdentityProvider> identityProviders) {
            if (identityProviders == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersResult", "identityProviders");
            }
            this.identityProviders = identityProviders;
            return this;
        }
        public Builder identityProviders(GetIdentityProvidersIdentityProvider... identityProviders) {
            return identityProviders(List.of(identityProviders));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersResult", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetIdentityProvidersResult build() {
            final var _resultValue = new GetIdentityProvidersResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.identityProviders = identityProviders;
            _resultValue.name = name;
            _resultValue.protocol = protocol;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
