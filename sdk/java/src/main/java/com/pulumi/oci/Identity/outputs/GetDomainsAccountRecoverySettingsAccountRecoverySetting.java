// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsAccountRecoverySettingsAccountRecoverySettingTag;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsAccountRecoverySettingsAccountRecoverySetting {
    private String accountRecoverySettingId;
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
     * @return An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    private String externalId;
    /**
     * @return The account recovery factor used (for example, email, mobile number (SMS), security questions, mobile application push or TOTP) to verify the identity of the user and reset the user&#39;s password.
     * 
     */
    private List<String> factors;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return Indicates how many minutes to disable account recovery for the user. The default value is 30 metric minutes.
     * 
     */
    private Integer lockoutDuration;
    /**
     * @return Indicates the maximum number of failed account recovery attempts allowed for the user.
     * 
     */
    private Integer maxIncorrectAttempts;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta> metas;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
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
    private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;

    private GetDomainsAccountRecoverySettingsAccountRecoverySetting() {}
    public String accountRecoverySettingId() {
        return this.accountRecoverySettingId;
    }
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
     * @return An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    public String externalId() {
        return this.externalId;
    }
    /**
     * @return The account recovery factor used (for example, email, mobile number (SMS), security questions, mobile application push or TOTP) to verify the identity of the user and reset the user&#39;s password.
     * 
     */
    public List<String> factors() {
        return this.factors;
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
    public List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy> idcsCreatedBies() {
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
    public List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return Indicates how many minutes to disable account recovery for the user. The default value is 30 metric minutes.
     * 
     */
    public Integer lockoutDuration() {
        return this.lockoutDuration;
    }
    /**
     * @return Indicates the maximum number of failed account recovery attempts allowed for the user.
     * 
     */
    public Integer maxIncorrectAttempts() {
        return this.maxIncorrectAttempts;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta> metas() {
        return this.metas;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
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
    public List<GetDomainsAccountRecoverySettingsAccountRecoverySettingTag> tags() {
        return this.tags;
    }
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public String tenancyOcid() {
        return this.tenancyOcid;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAccountRecoverySettingsAccountRecoverySetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accountRecoverySettingId;
        private List<String> attributeSets;
        private String attributes;
        private String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String domainOcid;
        private String externalId;
        private List<String> factors;
        private String id;
        private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private Integer lockoutDuration;
        private Integer maxIncorrectAttempts;
        private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta> metas;
        private String ocid;
        private String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsAccountRecoverySettingsAccountRecoverySettingTag> tags;
        private String tenancyOcid;
        public Builder() {}
        public Builder(GetDomainsAccountRecoverySettingsAccountRecoverySetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accountRecoverySettingId = defaults.accountRecoverySettingId;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.externalId = defaults.externalId;
    	      this.factors = defaults.factors;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.lockoutDuration = defaults.lockoutDuration;
    	      this.maxIncorrectAttempts = defaults.maxIncorrectAttempts;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
        }

        @CustomType.Setter
        public Builder accountRecoverySettingId(String accountRecoverySettingId) {
            this.accountRecoverySettingId = Objects.requireNonNull(accountRecoverySettingId);
            return this;
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
        public Builder externalId(String externalId) {
            this.externalId = Objects.requireNonNull(externalId);
            return this;
        }
        @CustomType.Setter
        public Builder factors(List<String> factors) {
            this.factors = Objects.requireNonNull(factors);
            return this;
        }
        public Builder factors(String... factors) {
            return factors(List.of(factors));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy> idcsCreatedBies) {
            this.idcsCreatedBies = Objects.requireNonNull(idcsCreatedBies);
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            this.idcsEndpoint = Objects.requireNonNull(idcsEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy> idcsLastModifiedBies) {
            this.idcsLastModifiedBies = Objects.requireNonNull(idcsLastModifiedBies);
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsAccountRecoverySettingsAccountRecoverySettingIdcsLastModifiedBy... idcsLastModifiedBies) {
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
        public Builder lockoutDuration(Integer lockoutDuration) {
            this.lockoutDuration = Objects.requireNonNull(lockoutDuration);
            return this;
        }
        @CustomType.Setter
        public Builder maxIncorrectAttempts(Integer maxIncorrectAttempts) {
            this.maxIncorrectAttempts = Objects.requireNonNull(maxIncorrectAttempts);
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta> metas) {
            this.metas = Objects.requireNonNull(metas);
            return this;
        }
        public Builder metas(GetDomainsAccountRecoverySettingsAccountRecoverySettingMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
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
        public Builder tags(List<GetDomainsAccountRecoverySettingsAccountRecoverySettingTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDomainsAccountRecoverySettingsAccountRecoverySettingTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            this.tenancyOcid = Objects.requireNonNull(tenancyOcid);
            return this;
        }
        public GetDomainsAccountRecoverySettingsAccountRecoverySetting build() {
            final var o = new GetDomainsAccountRecoverySettingsAccountRecoverySetting();
            o.accountRecoverySettingId = accountRecoverySettingId;
            o.attributeSets = attributeSets;
            o.attributes = attributes;
            o.authorization = authorization;
            o.compartmentOcid = compartmentOcid;
            o.deleteInProgress = deleteInProgress;
            o.domainOcid = domainOcid;
            o.externalId = externalId;
            o.factors = factors;
            o.id = id;
            o.idcsCreatedBies = idcsCreatedBies;
            o.idcsEndpoint = idcsEndpoint;
            o.idcsLastModifiedBies = idcsLastModifiedBies;
            o.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            o.idcsPreventedOperations = idcsPreventedOperations;
            o.lockoutDuration = lockoutDuration;
            o.maxIncorrectAttempts = maxIncorrectAttempts;
            o.metas = metas;
            o.ocid = ocid;
            o.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            o.schemas = schemas;
            o.tags = tags;
            o.tenancyOcid = tenancyOcid;
            return o;
        }
    }
}