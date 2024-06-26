// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyTag;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser;
import com.pulumi.oci.Identity.outputs.GetDomainsApiKeyUser;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsApiKeyResult {
    private String apiKeyId;
    private @Nullable List<String> attributeSets;
    private @Nullable String attributes;
    private @Nullable String authorization;
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
     * @return Fingerprint
     * 
     */
    private String fingerprint;
    /**
     * @return Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider&#39;s entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsApiKeyIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsApiKeyIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return Key or name of the tag.
     * 
     */
    private String key;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsApiKeyMeta> metas;
    /**
     * @return The user&#39;s OCID.
     * 
     */
    private String ocid;
    private @Nullable String resourceTypeSchemaVersion;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsApiKeyTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Controls whether a user can update themselves or not via User related APIs
     * 
     */
    private List<GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    /**
     * @return The user linked to the API key.
     * 
     */
    private List<GetDomainsApiKeyUser> users;

    private GetDomainsApiKeyResult() {}
    public String apiKeyId() {
        return this.apiKeyId;
    }
    public List<String> attributeSets() {
        return this.attributeSets == null ? List.of() : this.attributeSets;
    }
    public Optional<String> attributes() {
        return Optional.ofNullable(this.attributes);
    }
    public Optional<String> authorization() {
        return Optional.ofNullable(this.authorization);
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
     * @return Fingerprint
     * 
     */
    public String fingerprint() {
        return this.fingerprint;
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
    public List<GetDomainsApiKeyIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsApiKeyIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return Key or name of the tag.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsApiKeyMeta> metas() {
        return this.metas;
    }
    /**
     * @return The user&#39;s OCID.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
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
    public List<GetDomainsApiKeyTag> tags() {
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
    public List<GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers() {
        return this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    }
    /**
     * @return The user linked to the API key.
     * 
     */
    public List<GetDomainsApiKeyUser> users() {
        return this.users;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsApiKeyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apiKeyId;
        private @Nullable List<String> attributeSets;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String description;
        private String domainOcid;
        private String fingerprint;
        private String id;
        private List<GetDomainsApiKeyIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsApiKeyIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String key;
        private List<GetDomainsApiKeyMeta> metas;
        private String ocid;
        private @Nullable String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsApiKeyTag> tags;
        private String tenancyOcid;
        private List<GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
        private List<GetDomainsApiKeyUser> users;
        public Builder() {}
        public Builder(GetDomainsApiKeyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiKeyId = defaults.apiKeyId;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.description = defaults.description;
    	      this.domainOcid = defaults.domainOcid;
    	      this.fingerprint = defaults.fingerprint;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.key = defaults.key;
    	      this.metas = defaults.metas;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = defaults.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
    	      this.users = defaults.users;
        }

        @CustomType.Setter
        public Builder apiKeyId(String apiKeyId) {
            if (apiKeyId == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "apiKeyId");
            }
            this.apiKeyId = apiKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder attributeSets(@Nullable List<String> attributeSets) {

            this.attributeSets = attributeSets;
            return this;
        }
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }
        @CustomType.Setter
        public Builder attributes(@Nullable String attributes) {

            this.attributes = attributes;
            return this;
        }
        @CustomType.Setter
        public Builder authorization(@Nullable String authorization) {

            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder fingerprint(String fingerprint) {
            if (fingerprint == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "fingerprint");
            }
            this.fingerprint = fingerprint;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsApiKeyIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsApiKeyIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsApiKeyIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsApiKeyIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsApiKeyMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsApiKeyMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {

            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsApiKeyTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsApiKeyTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(List<GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers) {
            if (urnietfparamsscimschemasoracleidcsextensionselfChangeUsers == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "urnietfparamsscimschemasoracleidcsextensionselfChangeUsers");
            }
            this.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
            return this;
        }
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUser... urnietfparamsscimschemasoracleidcsextensionselfChangeUsers) {
            return urnietfparamsscimschemasoracleidcsextensionselfChangeUsers(List.of(urnietfparamsscimschemasoracleidcsextensionselfChangeUsers));
        }
        @CustomType.Setter
        public Builder users(List<GetDomainsApiKeyUser> users) {
            if (users == null) {
              throw new MissingRequiredPropertyException("GetDomainsApiKeyResult", "users");
            }
            this.users = users;
            return this;
        }
        public Builder users(GetDomainsApiKeyUser... users) {
            return users(List.of(users));
        }
        public GetDomainsApiKeyResult build() {
            final var _resultValue = new GetDomainsApiKeyResult();
            _resultValue.apiKeyId = apiKeyId;
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.description = description;
            _resultValue.domainOcid = domainOcid;
            _resultValue.fingerprint = fingerprint;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.key = key;
            _resultValue.metas = metas;
            _resultValue.ocid = ocid;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.schemas = schemas;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.urnietfparamsscimschemasoracleidcsextensionselfChangeUsers = urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
            _resultValue.users = users;
            return _resultValue;
        }
    }
}
