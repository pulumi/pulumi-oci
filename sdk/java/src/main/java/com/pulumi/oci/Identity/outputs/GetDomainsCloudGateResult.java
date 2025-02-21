// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateMapping;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateOauthClient;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateServer;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateTag;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateUpstreamServer;
import com.pulumi.oci.Identity.outputs.GetDomainsCloudGateUpstreamServerGroup;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsCloudGateResult {
    /**
     * @return Activation status for this Cloud Gate
     * 
     */
    private Boolean active;
    private @Nullable List<String> attributeSets;
    private @Nullable String attributes;
    private @Nullable String authorization;
    private String cloudGateId;
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
     * @return Brief description for this Cloud Gate
     * 
     */
    private String description;
    /**
     * @return Display name of upstream server
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
    private List<GetDomainsCloudGateIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsCloudGateIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return Indicates whether this resource was created by OPC
     * 
     */
    private Boolean isOpcService;
    /**
     * @return Last updated timestamp for this CloudGate&#39;s servers and mappings.
     * 
     */
    private String lastModifiedTime;
    /**
     * @return A list of Cloud Gate Mappings that map Apps to this Cloud Gate
     * 
     */
    private List<GetDomainsCloudGateMapping> mappings;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsCloudGateMeta> metas;
    /**
     * @return A reference to the OAuth client App used by this Cloud Gate instance.
     * 
     */
    private List<GetDomainsCloudGateOauthClient> oauthClients;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
     * @return A list of Server Blocks on this Cloud Gate
     * 
     */
    private List<GetDomainsCloudGateServer> servers;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsCloudGateTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;
    /**
     * @return Type of Cloud Gate
     * 
     */
    private String type;
    /**
     * @return A list of upstream server groups
     * 
     */
    private List<GetDomainsCloudGateUpstreamServerGroup> upstreamServerGroups;
    /**
     * @return A list of upstream servers
     * 
     */
    private List<GetDomainsCloudGateUpstreamServer> upstreamServers;

    private GetDomainsCloudGateResult() {}
    /**
     * @return Activation status for this Cloud Gate
     * 
     */
    public Boolean active() {
        return this.active;
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
    public String cloudGateId() {
        return this.cloudGateId;
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
     * @return Brief description for this Cloud Gate
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Display name of upstream server
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
    public List<GetDomainsCloudGateIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsCloudGateIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return Indicates whether this resource was created by OPC
     * 
     */
    public Boolean isOpcService() {
        return this.isOpcService;
    }
    /**
     * @return Last updated timestamp for this CloudGate&#39;s servers and mappings.
     * 
     */
    public String lastModifiedTime() {
        return this.lastModifiedTime;
    }
    /**
     * @return A list of Cloud Gate Mappings that map Apps to this Cloud Gate
     * 
     */
    public List<GetDomainsCloudGateMapping> mappings() {
        return this.mappings;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsCloudGateMeta> metas() {
        return this.metas;
    }
    /**
     * @return A reference to the OAuth client App used by this Cloud Gate instance.
     * 
     */
    public List<GetDomainsCloudGateOauthClient> oauthClients() {
        return this.oauthClients;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
     * @return A list of Server Blocks on this Cloud Gate
     * 
     */
    public List<GetDomainsCloudGateServer> servers() {
        return this.servers;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsCloudGateTag> tags() {
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
     * @return Type of Cloud Gate
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return A list of upstream server groups
     * 
     */
    public List<GetDomainsCloudGateUpstreamServerGroup> upstreamServerGroups() {
        return this.upstreamServerGroups;
    }
    /**
     * @return A list of upstream servers
     * 
     */
    public List<GetDomainsCloudGateUpstreamServer> upstreamServers() {
        return this.upstreamServers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsCloudGateResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean active;
        private @Nullable List<String> attributeSets;
        private @Nullable String attributes;
        private @Nullable String authorization;
        private String cloudGateId;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String description;
        private String displayName;
        private String domainOcid;
        private String id;
        private List<GetDomainsCloudGateIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsCloudGateIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private Boolean isOpcService;
        private String lastModifiedTime;
        private List<GetDomainsCloudGateMapping> mappings;
        private List<GetDomainsCloudGateMeta> metas;
        private List<GetDomainsCloudGateOauthClient> oauthClients;
        private String ocid;
        private @Nullable String resourceTypeSchemaVersion;
        private List<String> schemas;
        private List<GetDomainsCloudGateServer> servers;
        private List<GetDomainsCloudGateTag> tags;
        private String tenancyOcid;
        private String type;
        private List<GetDomainsCloudGateUpstreamServerGroup> upstreamServerGroups;
        private List<GetDomainsCloudGateUpstreamServer> upstreamServers;
        public Builder() {}
        public Builder(GetDomainsCloudGateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.active = defaults.active;
    	      this.attributeSets = defaults.attributeSets;
    	      this.attributes = defaults.attributes;
    	      this.authorization = defaults.authorization;
    	      this.cloudGateId = defaults.cloudGateId;
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
    	      this.isOpcService = defaults.isOpcService;
    	      this.lastModifiedTime = defaults.lastModifiedTime;
    	      this.mappings = defaults.mappings;
    	      this.metas = defaults.metas;
    	      this.oauthClients = defaults.oauthClients;
    	      this.ocid = defaults.ocid;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.schemas = defaults.schemas;
    	      this.servers = defaults.servers;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
    	      this.type = defaults.type;
    	      this.upstreamServerGroups = defaults.upstreamServerGroups;
    	      this.upstreamServers = defaults.upstreamServers;
        }

        @CustomType.Setter
        public Builder active(Boolean active) {
            if (active == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "active");
            }
            this.active = active;
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
        public Builder cloudGateId(String cloudGateId) {
            if (cloudGateId == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "cloudGateId");
            }
            this.cloudGateId = cloudGateId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsCloudGateIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsCloudGateIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsCloudGateIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsCloudGateIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder isOpcService(Boolean isOpcService) {
            if (isOpcService == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "isOpcService");
            }
            this.isOpcService = isOpcService;
            return this;
        }
        @CustomType.Setter
        public Builder lastModifiedTime(String lastModifiedTime) {
            if (lastModifiedTime == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "lastModifiedTime");
            }
            this.lastModifiedTime = lastModifiedTime;
            return this;
        }
        @CustomType.Setter
        public Builder mappings(List<GetDomainsCloudGateMapping> mappings) {
            if (mappings == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "mappings");
            }
            this.mappings = mappings;
            return this;
        }
        public Builder mappings(GetDomainsCloudGateMapping... mappings) {
            return mappings(List.of(mappings));
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsCloudGateMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsCloudGateMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder oauthClients(List<GetDomainsCloudGateOauthClient> oauthClients) {
            if (oauthClients == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "oauthClients");
            }
            this.oauthClients = oauthClients;
            return this;
        }
        public Builder oauthClients(GetDomainsCloudGateOauthClient... oauthClients) {
            return oauthClients(List.of(oauthClients));
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "ocid");
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
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder servers(List<GetDomainsCloudGateServer> servers) {
            if (servers == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "servers");
            }
            this.servers = servers;
            return this;
        }
        public Builder servers(GetDomainsCloudGateServer... servers) {
            return servers(List.of(servers));
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsCloudGateTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsCloudGateTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder upstreamServerGroups(List<GetDomainsCloudGateUpstreamServerGroup> upstreamServerGroups) {
            if (upstreamServerGroups == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "upstreamServerGroups");
            }
            this.upstreamServerGroups = upstreamServerGroups;
            return this;
        }
        public Builder upstreamServerGroups(GetDomainsCloudGateUpstreamServerGroup... upstreamServerGroups) {
            return upstreamServerGroups(List.of(upstreamServerGroups));
        }
        @CustomType.Setter
        public Builder upstreamServers(List<GetDomainsCloudGateUpstreamServer> upstreamServers) {
            if (upstreamServers == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateResult", "upstreamServers");
            }
            this.upstreamServers = upstreamServers;
            return this;
        }
        public Builder upstreamServers(GetDomainsCloudGateUpstreamServer... upstreamServers) {
            return upstreamServers(List.of(upstreamServers));
        }
        public GetDomainsCloudGateResult build() {
            final var _resultValue = new GetDomainsCloudGateResult();
            _resultValue.active = active;
            _resultValue.attributeSets = attributeSets;
            _resultValue.attributes = attributes;
            _resultValue.authorization = authorization;
            _resultValue.cloudGateId = cloudGateId;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.domainOcid = domainOcid;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.isOpcService = isOpcService;
            _resultValue.lastModifiedTime = lastModifiedTime;
            _resultValue.mappings = mappings;
            _resultValue.metas = metas;
            _resultValue.oauthClients = oauthClients;
            _resultValue.ocid = ocid;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.schemas = schemas;
            _resultValue.servers = servers;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            _resultValue.type = type;
            _resultValue.upstreamServerGroups = upstreamServerGroups;
            _resultValue.upstreamServers = upstreamServers;
            return _resultValue;
        }
    }
}
