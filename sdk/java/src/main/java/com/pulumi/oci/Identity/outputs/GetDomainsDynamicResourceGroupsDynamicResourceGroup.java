// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupTag;
import com.pulumi.oci.Identity.outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsDynamicResourceGroupsDynamicResourceGroup {
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
     * @return text that explains the purpose of this Dynamic Resource Group
     * 
     */
    private String description;
    /**
     * @return User-friendly, mutable identifier
     * 
     */
    private String displayName;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return A list of appRoles that are currently granted to this Dynamic Resource Group.  The Identity service will assert these AppRoles for any resource that satisfies the matching-rule of this DynamicResourceGroup.
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole> dynamicGroupAppRoles;
    /**
     * @return Grants assigned to group
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant> grants;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
     * 
     */
    private String matchingRule;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta> metas;
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
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Oracle Cloud Infrastructure Tags.
     * 
     */
    private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag> urnietfparamsscimschemasoracleidcsextensionOciTags;

    private GetDomainsDynamicResourceGroupsDynamicResourceGroup() {}
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
     * @return text that explains the purpose of this Dynamic Resource Group
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return User-friendly, mutable identifier
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return A list of appRoles that are currently granted to this Dynamic Resource Group.  The Identity service will assert these AppRoles for any resource that satisfies the matching-rule of this DynamicResourceGroup.
     * 
     */
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole> dynamicGroupAppRoles() {
        return this.dynamicGroupAppRoles;
    }
    /**
     * @return Grants assigned to group
     * 
     */
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant> grants() {
        return this.grants;
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
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy> idcsCreatedBies() {
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
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
     * 
     */
    public String matchingRule() {
        return this.matchingRule;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta> metas() {
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
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupTag> tags() {
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
     * @return Oracle Cloud Infrastructure Tags.
     * 
     */
    public List<GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag> urnietfparamsscimschemasoracleidcsextensionOciTags() {
        return this.urnietfparamsscimschemasoracleidcsextensionOciTags;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsDynamicResourceGroupsDynamicResourceGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> attributeSets;
        private String attributes;
        private String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String description;
        private String displayName;
        private String domainOcid;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole> dynamicGroupAppRoles;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant> grants;
        private String id;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String matchingRule;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta> metas;
        private String ocid;
        private String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupTag> tags;
        private String tenancyOcid;
        private List<GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag> urnietfparamsscimschemasoracleidcsextensionOciTags;
        public Builder() {}
        public Builder(GetDomainsDynamicResourceGroupsDynamicResourceGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.domainOcid = defaults.domainOcid;
    	      this.dynamicGroupAppRoles = defaults.dynamicGroupAppRoles;
    	      this.grants = defaults.grants;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.matchingRule = defaults.matchingRule;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.urnietfparamsscimschemasoracleidcsextensionOciTags = defaults.urnietfparamsscimschemasoracleidcsextensionOciTags;
        }

        @CustomType.Setter
        public Builder attributeSets(List<String> attributeSets) {
            if (attributeSets == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "attributeSets");
            }
            this.attributeSets = attributeSets;
            return this;
        }
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }
        @CustomType.Setter
        public Builder attributes(String attributes) {
            if (attributes == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "attributes");
            }
            this.attributes = attributes;
            return this;
        }
        @CustomType.Setter
        public Builder authorization(String authorization) {
            if (authorization == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "authorization");
            }
            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder dynamicGroupAppRoles(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole> dynamicGroupAppRoles) {
            if (dynamicGroupAppRoles == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "dynamicGroupAppRoles");
            }
            this.dynamicGroupAppRoles = dynamicGroupAppRoles;
            return this;
        }
        public Builder dynamicGroupAppRoles(GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRole... dynamicGroupAppRoles) {
            return dynamicGroupAppRoles(List.of(dynamicGroupAppRoles));
        }
        @CustomType.Setter
        public Builder grants(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant> grants) {
            if (grants == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "grants");
            }
            this.grants = grants;
            return this;
        }
        public Builder grants(GetDomainsDynamicResourceGroupsDynamicResourceGroupGrant... grants) {
            return grants(List.of(grants));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder matchingRule(String matchingRule) {
            if (matchingRule == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "matchingRule");
            }
            this.matchingRule = matchingRule;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsDynamicResourceGroupsDynamicResourceGroupMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            if (resourceTypeSchemaVersion == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "resourceTypeSchemaVersion");
            }
            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsDynamicResourceGroupsDynamicResourceGroupTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(List<GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag> urnietfparamsscimschemasoracleidcsextensionOciTags) {
            if (urnietfparamsscimschemasoracleidcsextensionOciTags == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupsDynamicResourceGroup", "urnietfparamsscimschemasoracleidcsextensionOciTags");
            }
            this.urnietfparamsscimschemasoracleidcsextensionOciTags = urnietfparamsscimschemasoracleidcsextensionOciTags;
            return this;
        }
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTag... urnietfparamsscimschemasoracleidcsextensionOciTags) {
            return urnietfparamsscimschemasoracleidcsextensionOciTags(List.of(urnietfparamsscimschemasoracleidcsextensionOciTags));
        }
        public GetDomainsDynamicResourceGroupsDynamicResourceGroup build() {
            final var _resultValue = new GetDomainsDynamicResourceGroupsDynamicResourceGroup();
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.domainOcid = domainOcid;
            _resultValue.dynamicGroupAppRoles = dynamicGroupAppRoles;
            _resultValue.grants = grants;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.matchingRule = matchingRule;
            _resultValue.metas = metas;
            _resultValue.ocid = ocid;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.schemas = schemas;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.urnietfparamsscimschemasoracleidcsextensionOciTags = urnietfparamsscimschemasoracleidcsextensionOciTags;
            return _resultValue;
        }
    }
}
