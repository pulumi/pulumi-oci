// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleApp;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleMember;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsAppRolesAppRoleTag;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsAppRolesAppRole {
    /**
     * @return If true, the role provides administrative access privileges.
     * 
     */
    private Boolean adminRole;
    /**
     * @return A unique identifier for the application that references this role.
     * 
     */
    private List<GetDomainsAppRolesAppRoleApp> apps;
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
     * @return If true, this AppRole can be granted to Apps.
     * 
     */
    private Boolean availableToClients;
    /**
     * @return If true, this AppRole can be granted to Groups.
     * 
     */
    private Boolean availableToGroups;
    /**
     * @return If true, this AppRole can be granted to Users.
     * 
     */
    private Boolean availableToUsers;
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
     * @return AppRole description
     * 
     */
    private String description;
    /**
     * @return AppRole name
     * 
     */
    private String displayName;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsAppRolesAppRoleIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsAppRolesAppRoleIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return The name of the legacy group associated with this AppRole.
     * 
     */
    private String legacyGroupName;
    /**
     * @return If true, indicates that this Oracle Identity Cloud Service AppRole can be granted to a delegated administrator whose scope is limited to users that are members of one or more groups.
     * 
     */
    private Boolean limitedToOneOrMoreGroups;
    /**
     * @return AppRole localization name
     * 
     */
    private String localizedDisplayName;
    /**
     * @return AppRole members - when requesting members attribute, it is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     */
    private List<GetDomainsAppRolesAppRoleMember> members;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsAppRolesAppRoleMeta> metas;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return If true, this AppRole is available automatically to every Oracle Identity Cloud Service User in this tenancy. There is no need to grant it to individual Users or Groups.
     * 
     */
    private Boolean public_;
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
    private List<GetDomainsAppRolesAppRoleTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return AppRole unique name
     * 
     */
    private String uniqueName;

    private GetDomainsAppRolesAppRole() {}
    /**
     * @return If true, the role provides administrative access privileges.
     * 
     */
    public Boolean adminRole() {
        return this.adminRole;
    }
    /**
     * @return A unique identifier for the application that references this role.
     * 
     */
    public List<GetDomainsAppRolesAppRoleApp> apps() {
        return this.apps;
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
     * @return If true, this AppRole can be granted to Apps.
     * 
     */
    public Boolean availableToClients() {
        return this.availableToClients;
    }
    /**
     * @return If true, this AppRole can be granted to Groups.
     * 
     */
    public Boolean availableToGroups() {
        return this.availableToGroups;
    }
    /**
     * @return If true, this AppRole can be granted to Users.
     * 
     */
    public Boolean availableToUsers() {
        return this.availableToUsers;
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
     * @return AppRole description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return AppRole name
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
    public List<GetDomainsAppRolesAppRoleIdcsCreatedBy> idcsCreatedBies() {
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
    public List<GetDomainsAppRolesAppRoleIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return The name of the legacy group associated with this AppRole.
     * 
     */
    public String legacyGroupName() {
        return this.legacyGroupName;
    }
    /**
     * @return If true, indicates that this Oracle Identity Cloud Service AppRole can be granted to a delegated administrator whose scope is limited to users that are members of one or more groups.
     * 
     */
    public Boolean limitedToOneOrMoreGroups() {
        return this.limitedToOneOrMoreGroups;
    }
    /**
     * @return AppRole localization name
     * 
     */
    public String localizedDisplayName() {
        return this.localizedDisplayName;
    }
    /**
     * @return AppRole members - when requesting members attribute, it is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     */
    public List<GetDomainsAppRolesAppRoleMember> members() {
        return this.members;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsAppRolesAppRoleMeta> metas() {
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
     * @return If true, this AppRole is available automatically to every Oracle Identity Cloud Service User in this tenancy. There is no need to grant it to individual Users or Groups.
     * 
     */
    public Boolean public_() {
        return this.public_;
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
    public List<GetDomainsAppRolesAppRoleTag> tags() {
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
     * @return AppRole unique name
     * 
     */
    public String uniqueName() {
        return this.uniqueName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppRolesAppRole defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean adminRole;
        private List<GetDomainsAppRolesAppRoleApp> apps;
        private List<String> attributeSets;
        private String attributes;
        private String authorization;
        private Boolean availableToClients;
        private Boolean availableToGroups;
        private Boolean availableToUsers;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String description;
        private String displayName;
        private String domainOcid;
        private String id;
        private List<GetDomainsAppRolesAppRoleIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsAppRolesAppRoleIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String legacyGroupName;
        private Boolean limitedToOneOrMoreGroups;
        private String localizedDisplayName;
        private List<GetDomainsAppRolesAppRoleMember> members;
        private List<GetDomainsAppRolesAppRoleMeta> metas;
        private String ocid;
        private Boolean public_;
        private String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsAppRolesAppRoleTag> tags;
        private String tenancyOcid;
        private String uniqueName;
        public Builder() {}
        public Builder(GetDomainsAppRolesAppRole defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminRole = defaults.adminRole;
    	      this.apps = defaults.apps;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.availableToClients = defaults.availableToClients;
    	      this.availableToGroups = defaults.availableToGroups;
    	      this.availableToUsers = defaults.availableToUsers;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.domainOcid = defaults.domainOcid;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.legacyGroupName = defaults.legacyGroupName;
    	      this.limitedToOneOrMoreGroups = defaults.limitedToOneOrMoreGroups;
    	      this.localizedDisplayName = defaults.localizedDisplayName;
    	      this.members = defaults.members;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.public_ = defaults.public_;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.uniqueName = defaults.uniqueName;
        }

        @CustomType.Setter
        public Builder adminRole(Boolean adminRole) {
            this.adminRole = Objects.requireNonNull(adminRole);
            return this;
        }
        @CustomType.Setter
        public Builder apps(List<GetDomainsAppRolesAppRoleApp> apps) {
            this.apps = Objects.requireNonNull(apps);
            return this;
        }
        public Builder apps(GetDomainsAppRolesAppRoleApp... apps) {
            return apps(List.of(apps));
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
        public Builder availableToClients(Boolean availableToClients) {
            this.availableToClients = Objects.requireNonNull(availableToClients);
            return this;
        }
        @CustomType.Setter
        public Builder availableToGroups(Boolean availableToGroups) {
            this.availableToGroups = Objects.requireNonNull(availableToGroups);
            return this;
        }
        @CustomType.Setter
        public Builder availableToUsers(Boolean availableToUsers) {
            this.availableToUsers = Objects.requireNonNull(availableToUsers);
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
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            this.domainOcid = Objects.requireNonNull(domainOcid);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsAppRolesAppRoleIdcsCreatedBy> idcsCreatedBies) {
            this.idcsCreatedBies = Objects.requireNonNull(idcsCreatedBies);
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsAppRolesAppRoleIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            this.idcsEndpoint = Objects.requireNonNull(idcsEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsAppRolesAppRoleIdcsLastModifiedBy> idcsLastModifiedBies) {
            this.idcsLastModifiedBies = Objects.requireNonNull(idcsLastModifiedBies);
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsAppRolesAppRoleIdcsLastModifiedBy... idcsLastModifiedBies) {
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
        public Builder legacyGroupName(String legacyGroupName) {
            this.legacyGroupName = Objects.requireNonNull(legacyGroupName);
            return this;
        }
        @CustomType.Setter
        public Builder limitedToOneOrMoreGroups(Boolean limitedToOneOrMoreGroups) {
            this.limitedToOneOrMoreGroups = Objects.requireNonNull(limitedToOneOrMoreGroups);
            return this;
        }
        @CustomType.Setter
        public Builder localizedDisplayName(String localizedDisplayName) {
            this.localizedDisplayName = Objects.requireNonNull(localizedDisplayName);
            return this;
        }
        @CustomType.Setter
        public Builder members(List<GetDomainsAppRolesAppRoleMember> members) {
            this.members = Objects.requireNonNull(members);
            return this;
        }
        public Builder members(GetDomainsAppRolesAppRoleMember... members) {
            return members(List.of(members));
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsAppRolesAppRoleMeta> metas) {
            this.metas = Objects.requireNonNull(metas);
            return this;
        }
        public Builder metas(GetDomainsAppRolesAppRoleMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
            return this;
        }
        @CustomType.Setter("public")
        public Builder public_(Boolean public_) {
            this.public_ = Objects.requireNonNull(public_);
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
        public Builder tags(List<GetDomainsAppRolesAppRoleTag> tags) {
            this.tags = Objects.requireNonNull(tags);
            return this;
        }
        public Builder tags(GetDomainsAppRolesAppRoleTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            this.tenancyOcid = Objects.requireNonNull(tenancyOcid);
            return this;
        }
        @CustomType.Setter
        public Builder uniqueName(String uniqueName) {
            this.uniqueName = Objects.requireNonNull(uniqueName);
            return this;
        }
        public GetDomainsAppRolesAppRole build() {
            final var o = new GetDomainsAppRolesAppRole();
            o.adminRole = adminRole;
            o.apps = apps;
            o.attributeSets = attributeSets;
            o.attributes = attributes;
            o.authorization = authorization;
            o.availableToClients = availableToClients;
            o.availableToGroups = availableToGroups;
            o.availableToUsers = availableToUsers;
            o.compartmentOcid = compartmentOcid;
            o.deleteInProgress = deleteInProgress;
            o.description = description;
            o.displayName = displayName;
            o.domainOcid = domainOcid;
            o.id = id;
            o.idcsCreatedBies = idcsCreatedBies;
            o.idcsEndpoint = idcsEndpoint;
            o.idcsLastModifiedBies = idcsLastModifiedBies;
            o.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            o.idcsPreventedOperations = idcsPreventedOperations;
            o.legacyGroupName = legacyGroupName;
            o.limitedToOneOrMoreGroups = limitedToOneOrMoreGroups;
            o.localizedDisplayName = localizedDisplayName;
            o.members = members;
            o.metas = metas;
            o.ocid = ocid;
            o.public_ = public_;
            o.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            o.schemas = schemas;
            o.tags = tags;
            o.tenancyOcid = tenancyOcid;
            o.uniqueName = uniqueName;
            return o;
        }
    }
}