// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetIdentityProvidersIdentityProvider {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private final String description;
    /**
     * @return Extra name value pairs associated with this identity provider. Example: `{&#34;clientId&#34;: &#34;app_sf3kdjf3&#34;}`
     * 
     */
    private final Map<String,Object> freeformAttributes;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the `IdentityProvider`.
     * 
     */
    private final String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private final String inactiveState;
    /**
     * @return The XML that contains the information required for federating Identity with SAML2 Identity Provider.
     * 
     */
    private final String metadata;
    /**
     * @return The URL for retrieving the identity provider&#39;s metadata, which contains information required for federating.
     * 
     */
    private final String metadataUrl;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private final String name;
    /**
     * @return The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).
     * 
     */
    private final String productType;
    /**
     * @return The protocol used for federation.
     * 
     */
    private final String protocol;
    /**
     * @return The URL to redirect federated users to for authentication with the identity provider.
     * 
     */
    private final String redirectUrl;
    /**
     * @return The identity provider&#39;s signing certificate used by the IAM Service to validate the SAML2 token.
     * 
     */
    private final String signingCertificate;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private final String state;
    /**
     * @return Date and time the `IdentityProvider` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetIdentityProvidersIdentityProvider(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("freeformAttributes") Map<String,Object> freeformAttributes,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("inactiveState") String inactiveState,
        @CustomType.Parameter("metadata") String metadata,
        @CustomType.Parameter("metadataUrl") String metadataUrl,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("productType") String productType,
        @CustomType.Parameter("protocol") String protocol,
        @CustomType.Parameter("redirectUrl") String redirectUrl,
        @CustomType.Parameter("signingCertificate") String signingCertificate,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.description = description;
        this.freeformAttributes = freeformAttributes;
        this.freeformTags = freeformTags;
        this.id = id;
        this.inactiveState = inactiveState;
        this.metadata = metadata;
        this.metadataUrl = metadataUrl;
        this.name = name;
        this.productType = productType;
        this.protocol = protocol;
        this.redirectUrl = redirectUrl;
        this.signingCertificate = signingCertificate;
        this.state = state;
        this.timeCreated = timeCreated;
    }

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
    public Map<String,Object> definedTags() {
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
    public Map<String,Object> freeformAttributes() {
        return this.freeformAttributes;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
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

    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private Map<String,Object> freeformAttributes;
        private Map<String,Object> freeformTags;
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

        public Builder() {
    	      // Empty
        }

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

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder freeformAttributes(Map<String,Object> freeformAttributes) {
            this.freeformAttributes = Objects.requireNonNull(freeformAttributes);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder inactiveState(String inactiveState) {
            this.inactiveState = Objects.requireNonNull(inactiveState);
            return this;
        }
        public Builder metadata(String metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        public Builder metadataUrl(String metadataUrl) {
            this.metadataUrl = Objects.requireNonNull(metadataUrl);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder productType(String productType) {
            this.productType = Objects.requireNonNull(productType);
            return this;
        }
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        public Builder redirectUrl(String redirectUrl) {
            this.redirectUrl = Objects.requireNonNull(redirectUrl);
            return this;
        }
        public Builder signingCertificate(String signingCertificate) {
            this.signingCertificate = Objects.requireNonNull(signingCertificate);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetIdentityProvidersIdentityProvider build() {
            return new GetIdentityProvidersIdentityProvider(compartmentId, definedTags, description, freeformAttributes, freeformTags, id, inactiveState, metadata, metadataUrl, name, productType, protocol, redirectUrl, signingCertificate, state, timeCreated);
        }
    }
}
