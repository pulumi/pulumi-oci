// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor;
import com.pulumi.oci.Identity.outputs.GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsMyTrustedUserAgentsMyTrustedUserAgent {
    /**
     * @return A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    private List<String> attributeSets;
    /**
     * @return A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    private String attributes;
    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    private String authorization;
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    private String compartmentOcid;
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    private Boolean deleteInProgress;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return Validation period of the trust token.
     * 
     */
    private String expiryTime;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy> idcsLastModifiedBies;
    /**
     * @return The release number when the resource was upgraded.
     * 
     */
    private String idcsLastUpgradedInRelease;
    /**
     * @return Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    private List<String> idcsPreventedOperations;
    /**
     * @return Indicates when this token was used lastime.
     * 
     */
    private String lastUsedOn;
    /**
     * @return The URI of the Resource being returned. This value MUST be the same as the Location HTTP response header.
     * 
     */
    private String location;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta> metas;
    private String myTrustedUserAgentId;
    /**
     * @return The name of the User Agent that the user wants the system to trust and to use in Multi-Factor Authentication.
     * 
     */
    private String name;
    /**
     * @return The OCID of the user
     * 
     */
    private String ocid;
    /**
     * @return User agent platform for which the trust token has been issued.
     * 
     */
    private String platform;
    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    private String resourceTypeSchemaVersion;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return The token type being created. This token is used as trusted and kmsi token.
     * 
     */
    private String tokenType;
    /**
     * @return Trust token for the user agent. This is a random string value that will be updated whenever a token that has been issued is verified successfully.
     * 
     */
    private String trustToken;
    /**
     * @return Trusted 2FA Factors
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor> trustedFactors;
    /**
     * @return user for whom the trust-token was issued
     * 
     */
    private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser> users;

    private GetDomainsMyTrustedUserAgentsMyTrustedUserAgent() {}
    /**
     * @return A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    public List<String> attributeSets() {
        return this.attributeSets;
    }
    /**
     * @return A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    public String attributes() {
        return this.attributes;
    }
    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public String authorization() {
        return this.authorization;
    }
    /**
     * @return Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    public String compartmentOcid() {
        return this.compartmentOcid;
    }
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    public Boolean deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return Validation period of the trust token.
     * 
     */
    public String expiryTime() {
        return this.expiryTime;
    }
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The User or App who created the Resource
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy> idcsLastModifiedBies() {
        return this.idcsLastModifiedBies;
    }
    /**
     * @return The release number when the resource was upgraded.
     * 
     */
    public String idcsLastUpgradedInRelease() {
        return this.idcsLastUpgradedInRelease;
    }
    /**
     * @return Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    public List<String> idcsPreventedOperations() {
        return this.idcsPreventedOperations;
    }
    /**
     * @return Indicates when this token was used lastime.
     * 
     */
    public String lastUsedOn() {
        return this.lastUsedOn;
    }
    /**
     * @return The URI of the Resource being returned. This value MUST be the same as the Location HTTP response header.
     * 
     */
    public String location() {
        return this.location;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta> metas() {
        return this.metas;
    }
    public String myTrustedUserAgentId() {
        return this.myTrustedUserAgentId;
    }
    /**
     * @return The name of the User Agent that the user wants the system to trust and to use in Multi-Factor Authentication.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OCID of the user
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return User agent platform for which the trust token has been issued.
     * 
     */
    public String platform() {
        return this.platform;
    }
    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public String resourceTypeSchemaVersion() {
        return this.resourceTypeSchemaVersion;
    }
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag> tags() {
        return this.tags;
    }
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public String tenancyOcid() {
        return this.tenancyOcid;
    }
    /**
     * @return The token type being created. This token is used as trusted and kmsi token.
     * 
     */
    public String tokenType() {
        return this.tokenType;
    }
    /**
     * @return Trust token for the user agent. This is a random string value that will be updated whenever a token that has been issued is verified successfully.
     * 
     */
    public String trustToken() {
        return this.trustToken;
    }
    /**
     * @return Trusted 2FA Factors
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor> trustedFactors() {
        return this.trustedFactors;
    }
    /**
     * @return user for whom the trust-token was issued
     * 
     */
    public List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser> users() {
        return this.users;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyTrustedUserAgentsMyTrustedUserAgent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> attributeSets;
        private String attributes;
        private String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String domainOcid;
        private String expiryTime;
        private String id;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String lastUsedOn;
        private String location;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta> metas;
        private String myTrustedUserAgentId;
        private String name;
        private String ocid;
        private String platform;
        private String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag> tags;
        private String tenancyOcid;
        private String tokenType;
        private String trustToken;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor> trustedFactors;
        private List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser> users;
        public Builder() {}
        public Builder(GetDomainsMyTrustedUserAgentsMyTrustedUserAgent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.expiryTime = defaults.expiryTime;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.lastUsedOn = defaults.lastUsedOn;
    	      this.location = defaults.location;
    	      this.metas = defaults.metas;
    	      this.myTrustedUserAgentId = defaults.myTrustedUserAgentId;
    	      this.name = defaults.name;
    	      this.ocid = defaults.ocid;
    	      this.platform = defaults.platform;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.tokenType = defaults.tokenType;
    	      this.trustToken = defaults.trustToken;
    	      this.trustedFactors = defaults.trustedFactors;
    	      this.users = defaults.users;
        }

        @CustomType.Setter
        public Builder attributeSets(List<String> attributeSets) {
            this.attributeSets = Objects.requireNonNull(attributeSets);
            return this;
        }
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }
        @CustomType.Setter
        public Builder attributes(String attributes) {
            this.attributes = Objects.requireNonNull(attributes);
            return this;
        }
        @CustomType.Setter
        public Builder authorization(String authorization) {
            this.authorization = Objects.requireNonNull(authorization);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            this.compartmentOcid = Objects.requireNonNull(compartmentOcid);
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            this.deleteInProgress = Objects.requireNonNull(deleteInProgress);
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            this.domainOcid = Objects.requireNonNull(domainOcid);
            return this;
        }
        @CustomType.Setter
        public Builder expiryTime(String expiryTime) {
            this.expiryTime = Objects.requireNonNull(expiryTime);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy> idcsCreatedBies) {
            this.idcsCreatedBies = Objects.requireNonNull(idcsCreatedBies);
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            this.idcsEndpoint = Objects.requireNonNull(idcsEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy> idcsLastModifiedBies) {
            this.idcsLastModifiedBies = Objects.requireNonNull(idcsLastModifiedBies);
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            this.idcsLastUpgradedInRelease = Objects.requireNonNull(idcsLastUpgradedInRelease);
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            this.idcsPreventedOperations = Objects.requireNonNull(idcsPreventedOperations);
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder lastUsedOn(String lastUsedOn) {
            this.lastUsedOn = Objects.requireNonNull(lastUsedOn);
            return this;
        }
        @CustomType.Setter
        public Builder location(String location) {
            this.location = Objects.requireNonNull(location);
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta> metas) {
            this.metas = Objects.requireNonNull(metas);
            return this;
        }
        public Builder metas(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder myTrustedUserAgentId(String myTrustedUserAgentId) {
            this.myTrustedUserAgentId = Objects.requireNonNull(myTrustedUserAgentId);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
            return this;
        }
        @CustomType.Setter
        public Builder platform(String platform) {
            this.platform = Objects.requireNonNull(platform);
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            this.resourceTypeSchemaVersion = Objects.requireNonNull(resourceTypeSchemaVersion);
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            this.schemas = Objects.requireNonNull(schemas);
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            this.tenancyOcid = Objects.requireNonNull(tenancyOcid);
            return this;
        }
        @CustomType.Setter
        public Builder tokenType(String tokenType) {
            this.tokenType = Objects.requireNonNull(tokenType);
            return this;
        }
        @CustomType.Setter
        public Builder trustToken(String trustToken) {
            this.trustToken = Objects.requireNonNull(trustToken);
            return this;
        }
        @CustomType.Setter
        public Builder trustedFactors(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor> trustedFactors) {
            this.trustedFactors = Objects.requireNonNull(trustedFactors);
            return this;
        }
        public Builder trustedFactors(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentTrustedFactor... trustedFactors) {
            return trustedFactors(List.of(trustedFactors));
        }
        @CustomType.Setter
        public Builder users(List<GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser> users) {
            this.users = Objects.requireNonNull(users);
            return this;
        }
        public Builder users(GetDomainsMyTrustedUserAgentsMyTrustedUserAgentUser... users) {
            return users(List.of(users));
        }
        public GetDomainsMyTrustedUserAgentsMyTrustedUserAgent build() {
            final var o = new GetDomainsMyTrustedUserAgentsMyTrustedUserAgent();
            o.attributeSets = attributeSets;
            o.attributes = attributes;
            o.authorization = authorization;
            o.compartmentOcid = compartmentOcid;
            o.deleteInProgress = deleteInProgress;
            o.domainOcid = domainOcid;
            o.expiryTime = expiryTime;
            o.id = id;
            o.idcsCreatedBies = idcsCreatedBies;
            o.idcsEndpoint = idcsEndpoint;
            o.idcsLastModifiedBies = idcsLastModifiedBies;
            o.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            o.idcsPreventedOperations = idcsPreventedOperations;
            o.lastUsedOn = lastUsedOn;
            o.location = location;
            o.metas = metas;
            o.myTrustedUserAgentId = myTrustedUserAgentId;
            o.name = name;
            o.ocid = ocid;
            o.platform = platform;
            o.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            o.schemas = schemas;
            o.tags = tags;
            o.tenancyOcid = tenancyOcid;
            o.tokenType = tokenType;
            o.trustToken = trustToken;
            o.trustedFactors = trustedFactors;
            o.users = users;
            return o;
        }
    }
}