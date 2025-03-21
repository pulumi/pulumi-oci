// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsMyUserDbCredentialsMyUserDbCredentialTag;
import com.pulumi.oci.Identity.outputs.GetDomainsMyUserDbCredentialsMyUserDbCredentialUser;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsMyUserDbCredentialsMyUserDbCredential {
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
    private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy> idcsCreatedBies;
    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies;
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
    private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta> metas;
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
    private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return The user linked to the database credential.
     * 
     */
    private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialUser> users;

    private GetDomainsMyUserDbCredentialsMyUserDbCredential() {}
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
    public List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy> idcsCreatedBies() {
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
    public List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies() {
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
    public List<GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta> metas() {
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
    public List<GetDomainsMyUserDbCredentialsMyUserDbCredentialTag> tags() {
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
     * @return The user linked to the database credential.
     * 
     */
    public List<GetDomainsMyUserDbCredentialsMyUserDbCredentialUser> users() {
        return this.users;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyUserDbCredentialsMyUserDbCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String authorization;
        private String compartmentOcid;
        private String dbPassword;
        private Boolean deleteInProgress;
        private String description;
        private String domainOcid;
        private Boolean expired;
        private String expiresOn;
        private String id;
        private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String lastSetDate;
        private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta> metas;
        private String mixedDbPassword;
        private String mixedSalt;
        private String name;
        private String ocid;
        private String resourceTypeSchemaVersion;
        private String salt;
        private List<String> schemas;
        private String status;
        private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialTag> tags;
        private String tenancyOcid;
        private List<GetDomainsMyUserDbCredentialsMyUserDbCredentialUser> users;
        public Builder() {}
        public Builder(GetDomainsMyUserDbCredentialsMyUserDbCredential defaults) {
    	      Objects.requireNonNull(defaults);
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
    	      this.users = defaults.users;
        }

        @CustomType.Setter
        public Builder authorization(String authorization) {
            if (authorization == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "authorization");
            }
            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder dbPassword(String dbPassword) {
            if (dbPassword == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "dbPassword");
            }
            this.dbPassword = dbPassword;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder expired(Boolean expired) {
            if (expired == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "expired");
            }
            this.expired = expired;
            return this;
        }
        @CustomType.Setter
        public Builder expiresOn(String expiresOn) {
            if (expiresOn == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "expiresOn");
            }
            this.expiresOn = expiresOn;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsMyUserDbCredentialsMyUserDbCredentialIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "idcsPreventedOperations");
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
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "lastSetDate");
            }
            this.lastSetDate = lastSetDate;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsMyUserDbCredentialsMyUserDbCredentialMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder mixedDbPassword(String mixedDbPassword) {
            if (mixedDbPassword == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "mixedDbPassword");
            }
            this.mixedDbPassword = mixedDbPassword;
            return this;
        }
        @CustomType.Setter
        public Builder mixedSalt(String mixedSalt) {
            if (mixedSalt == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "mixedSalt");
            }
            this.mixedSalt = mixedSalt;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            if (resourceTypeSchemaVersion == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "resourceTypeSchemaVersion");
            }
            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder salt(String salt) {
            if (salt == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "salt");
            }
            this.salt = salt;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "schemas");
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
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsMyUserDbCredentialsMyUserDbCredentialTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsMyUserDbCredentialsMyUserDbCredentialTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder users(List<GetDomainsMyUserDbCredentialsMyUserDbCredentialUser> users) {
            if (users == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialsMyUserDbCredential", "users");
            }
            this.users = users;
            return this;
        }
        public Builder users(GetDomainsMyUserDbCredentialsMyUserDbCredentialUser... users) {
            return users(List.of(users));
        }
        public GetDomainsMyUserDbCredentialsMyUserDbCredential build() {
            final var _resultValue = new GetDomainsMyUserDbCredentialsMyUserDbCredential();
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
            _resultValue.users = users;
            return _resultValue;
        }
    }
}
