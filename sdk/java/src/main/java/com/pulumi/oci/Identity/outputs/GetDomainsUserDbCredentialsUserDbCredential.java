// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialTag;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser;
import com.pulumi.oci.Identity.outputs.GetDomainsUserDbCredentialsUserDbCredentialUser;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUserDbCredentialsUserDbCredential {
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
     * @return The user&#39;s database password.
     * 
     */
    private String dbPassword;
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    private Boolean deleteInProgress;
    /**
     * @return Description
     * 
     */
    private String description;
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return Indicates that the database password has expired.
     * 
     */
    private Boolean expired;
    /**
     * @return When the user credential expires.
     * 
     */
    private String expiresOn;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return A DateTime that specifies the date and time when the current database password was set.
     * 
     */
    private String lastSetDate;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialMeta> metas;
    /**
     * @return The user&#39;s database password with mixed salt.
     * 
     */
    private String mixedDbPassword;
    /**
     * @return The mixed salt of the password.
     * 
     */
    private String mixedSalt;
    /**
     * @return The username.
     * 
     */
    private String name;
    /**
     * @return The user&#39;s OCID.
     * 
     */
    private String ocid;
    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    private String resourceTypeSchemaVersion;
    /**
     * @return The salt of the password.
     * 
     */
    private String salt;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return User credential status
     * 
     */
    private String status;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Controls whether a user can update themselves or not via User related APIs
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    /**
     * @return The user linked to the database credential.
     * 
     */
    private List<GetDomainsUserDbCredentialsUserDbCredentialUser> users;

    private GetDomainsUserDbCredentialsUserDbCredential() {}
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
     * @return The user&#39;s database password.
     * 
     */
    public String dbPassword() {
        return this.dbPassword;
    }
    /**
     * @return A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    public Boolean deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * @return Description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return Indicates that the database password has expired.
     * 
     */
    public Boolean expired() {
        return this.expired;
    }
    /**
     * @return When the user credential expires.
     * 
     */
    public String expiresOn() {
        return this.expiresOn;
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
    public List<GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy> idcsCreatedBies() {
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
    public List<GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return A DateTime that specifies the date and time when the current database password was set.
     * 
     */
    public String lastSetDate() {
        return this.lastSetDate;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsUserDbCredentialsUserDbCredentialMeta> metas() {
        return this.metas;
    }
    /**
     * @return The user&#39;s database password with mixed salt.
     * 
     */
    public String mixedDbPassword() {
        return this.mixedDbPassword;
    }
    /**
     * @return The mixed salt of the password.
     * 
     */
    public String mixedSalt() {
        return this.mixedSalt;
    }
    /**
     * @return The username.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The user&#39;s OCID.
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
     * @return The salt of the password.
     * 
     */
    public String salt() {
        return this.salt;
    }
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return User credential status
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsUserDbCredentialsUserDbCredentialTag> tags() {
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
     * @return Controls whether a user can update themselves or not via User related APIs
     * 
     */
    public List<GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers() {
        return this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    }
    /**
     * @return The user linked to the database credential.
     * 
     */
    public List<GetDomainsUserDbCredentialsUserDbCredentialUser> users() {
        return this.users;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserDbCredentialsUserDbCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> attributeSets;
        private String attributes;
        private String authorization;
        private String compartmentOcid;
        private String dbPassword;
        private Boolean deleteInProgress;
        private String description;
        private String domainOcid;
        private Boolean expired;
        private String expiresOn;
        private String id;
        private List<GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String lastSetDate;
        private List<GetDomainsUserDbCredentialsUserDbCredentialMeta> metas;
        private String mixedDbPassword;
        private String mixedSalt;
        private String name;
        private String ocid;
        private String resourceTypeSchemaVersion;
        private String salt;
        private List<String> schemas;
        private String status;
        private List<GetDomainsUserDbCredentialsUserDbCredentialTag> tags;
        private String tenancyOcid;
        private List<GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
        private List<GetDomainsUserDbCredentialsUserDbCredentialUser> users;
        public Builder() {}
        public Builder(GetDomainsUserDbCredentialsUserDbCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.dbPassword = defaults.dbPassword;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.description = defaults.description;
    	      this.domainOcid = defaults.domainOcid;
    	      this.expired = defaults.expired;
    	      this.expiresOn = defaults.expiresOn;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.lastSetDate = defaults.lastSetDate;
    	      this.metas = defaults.metas;
    	      this.mixedDbPassword = defaults.mixedDbPassword;
    	      this.mixedSalt = defaults.mixedSalt;
    	      this.name = defaults.name;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.salt = defaults.salt;
    	      this.schemas = defaults.schemas;
    	      this.status = defaults.status;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = defaults.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    	      this.users = defaults.users;
        }

        @CustomType.Setter
        public Builder attributeSets(List<String> attributeSets) {
            if (attributeSets == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "attributeSets");
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
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "attributes");
            }
            this.attributes = attributes;
            return this;
        }
        @CustomType.Setter
        public Builder authorization(String authorization) {
            if (authorization == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "authorization");
            }
            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder dbPassword(String dbPassword) {
            if (dbPassword == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "dbPassword");
            }
            this.dbPassword = dbPassword;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder expired(Boolean expired) {
            if (expired == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "expired");
            }
            this.expired = expired;
            return this;
        }
        @CustomType.Setter
        public Builder expiresOn(String expiresOn) {
            if (expiresOn == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "expiresOn");
            }
            this.expiresOn = expiresOn;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsUserDbCredentialsUserDbCredentialIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsUserDbCredentialsUserDbCredentialIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder lastSetDate(String lastSetDate) {
            if (lastSetDate == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "lastSetDate");
            }
            this.lastSetDate = lastSetDate;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsUserDbCredentialsUserDbCredentialMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsUserDbCredentialsUserDbCredentialMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder mixedDbPassword(String mixedDbPassword) {
            if (mixedDbPassword == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "mixedDbPassword");
            }
            this.mixedDbPassword = mixedDbPassword;
            return this;
        }
        @CustomType.Setter
        public Builder mixedSalt(String mixedSalt) {
            if (mixedSalt == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "mixedSalt");
            }
            this.mixedSalt = mixedSalt;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            if (resourceTypeSchemaVersion == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "resourceTypeSchemaVersion");
            }
            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder salt(String salt) {
            if (salt == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "salt");
            }
            this.salt = salt;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsUserDbCredentialsUserDbCredentialTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsUserDbCredentialsUserDbCredentialTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(List<GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers) {
            if (urnietfparamsscimschemasoracleidcsextensionselfChangeUsers == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "urnietfparamsscimschemasoracleidcsextensionselfChangeUsers");
            }
            this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
            return this;
        }
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(GetDomainsUserDbCredentialsUserDbCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser... urnietfparamsscimschemasoracleidcsextensionselfChangeUsers) {
            return urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(List.of(urnietfparamsscimschemasoracleidcsextensionselfChangeUsers));
        }
        @CustomType.Setter
        public Builder users(List<GetDomainsUserDbCredentialsUserDbCredentialUser> users) {
            if (users == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserDbCredentialsUserDbCredential", "users");
            }
            this.users = users;
            return this;
        }
        public Builder users(GetDomainsUserDbCredentialsUserDbCredentialUser... users) {
            return users(List.of(users));
        }
        public GetDomainsUserDbCredentialsUserDbCredential build() {
            final var _resultValue = new GetDomainsUserDbCredentialsUserDbCredential();
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.dbPassword = dbPassword;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.description = description;
            _resultValue.domainOcid = domainOcid;
            _resultValue.expired = expired;
            _resultValue.expiresOn = expiresOn;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.lastSetDate = lastSetDate;
            _resultValue.metas = metas;
            _resultValue.mixedDbPassword = mixedDbPassword;
            _resultValue.mixedSalt = mixedSalt;
            _resultValue.name = name;
            _resultValue.ocid = ocid;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.salt = salt;
            _resultValue.schemas = schemas;
            _resultValue.status = status;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
            _resultValue.users = users;
            return _resultValue;
        }
    }
}
