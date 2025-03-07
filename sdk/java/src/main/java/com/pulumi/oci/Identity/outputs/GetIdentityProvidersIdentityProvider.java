// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetIdentityProvidersIdentityProvider {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String description;
    /**
     * @return Extra name value pairs associated with this identity provider. Example: `{&#34;clientId&#34;: &#34;app_sf3kdjf3&#34;}`
     * 
     */
    private Map<String,String> freeformAttributes;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the `IdentityProvider`.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveState;
    /**
     * @return The XML that contains the information required for federating Identity with SAML2 Identity Provider.
     * 
     */
    private String metadata;
    /**
     * @return The URL for retrieving the identity provider&#39;s metadata, which contains information required for federating.
     * 
     */
    private String metadataUrl;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).
     * 
     */
    private String productType;
    /**
     * @return The protocol used for federation.
     * 
     */
    private String protocol;
    /**
     * @return The URL to redirect federated users to for authentication with the identity provider.
     * 
     */
    private String redirectUrl;
    /**
     * @return The identity provider&#39;s signing certificate used by the IAM Service to validate the SAML2 token.
     * 
     */
    private String signingCertificate;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return Date and time the `IdentityProvider` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetIdentityProvidersIdentityProvider() {}
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Extra name value pairs associated with this identity provider. Example: `{&#34;clientId&#34;: &#34;app_sf3kdjf3&#34;}`
     * 
     */
    public Map<String,String> freeformAttributes() {
        return this.freeformAttributes;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the `IdentityProvider`.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return The XML that contains the information required for federating Identity with SAML2 Identity Provider.
     * 
     */
    public String metadata() {
        return this.metadata;
    }
    /**
     * @return The URL for retrieving the identity provider&#39;s metadata, which contains information required for federating.
     * 
     */
    public String metadataUrl() {
        return this.metadataUrl;
    }
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).
     * 
     */
    public String productType() {
        return this.productType;
    }
    /**
     * @return The protocol used for federation.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return The URL to redirect federated users to for authentication with the identity provider.
     * 
     */
    public String redirectUrl() {
        return this.redirectUrl;
    }
    /**
     * @return The identity provider&#39;s signing certificate used by the IAM Service to validate the SAML2 token.
     * 
     */
    public String signingCertificate() {
        return this.signingCertificate;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the `IdentityProvider` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIdentityProvidersIdentityProvider defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private Map<String,String> freeformAttributes;
        private Map<String,String> freeformTags;
        private String id;
        private String inactiveState;
        private String metadata;
        private String metadataUrl;
        private String name;
        private String productType;
        private String protocol;
        private String redirectUrl;
        private String signingCertificate;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetIdentityProvidersIdentityProvider defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.freeformAttributes = defaults.freeformAttributes;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.inactiveState = defaults.inactiveState;
    	      this.metadata = defaults.metadata;
    	      this.metadataUrl = defaults.metadataUrl;
    	      this.name = defaults.name;
    	      this.productType = defaults.productType;
    	      this.protocol = defaults.protocol;
    	      this.redirectUrl = defaults.redirectUrl;
    	      this.signingCertificate = defaults.signingCertificate;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder freeformAttributes(Map<String,String> freeformAttributes) {
            if (freeformAttributes == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "freeformAttributes");
            }
            this.freeformAttributes = freeformAttributes;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            if (inactiveState == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "inactiveState");
            }
            this.inactiveState = inactiveState;
            return this;
        }
        @CustomType.Setter
        public Builder metadata(String metadata) {
            if (metadata == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "metadata");
            }
            this.metadata = metadata;
            return this;
        }
        @CustomType.Setter
        public Builder metadataUrl(String metadataUrl) {
            if (metadataUrl == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "metadataUrl");
            }
            this.metadataUrl = metadataUrl;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder productType(String productType) {
            if (productType == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "productType");
            }
            this.productType = productType;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder redirectUrl(String redirectUrl) {
            if (redirectUrl == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "redirectUrl");
            }
            this.redirectUrl = redirectUrl;
            return this;
        }
        @CustomType.Setter
        public Builder signingCertificate(String signingCertificate) {
            if (signingCertificate == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "signingCertificate");
            }
            this.signingCertificate = signingCertificate;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetIdentityProvidersIdentityProvider", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetIdentityProvidersIdentityProvider build() {
            final var _resultValue = new GetIdentityProvidersIdentityProvider();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.freeformAttributes = freeformAttributes;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.inactiveState = inactiveState;
            _resultValue.metadata = metadata;
            _resultValue.metadataUrl = metadataUrl;
            _resultValue.name = name;
            _resultValue.productType = productType;
            _resultValue.protocol = protocol;
            _resultValue.redirectUrl = redirectUrl;
            _resultValue.signingCertificate = signingCertificate;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
