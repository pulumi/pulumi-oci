// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsMyCompletedApprovalIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyCompletedApprovalIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyCompletedApprovalMeta;
import com.pulumi.oci.Identity.outputs.GetDomainsMyCompletedApprovalTag;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDomainsMyCompletedApprovalResult {
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
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    private String domainOcid;
    /**
     * @return Time by when ApprovalWorkflowInstance expires
     * 
     */
    private String expires;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The User or App who created the Resource
     * 
     */
    private List<GetDomainsMyCompletedApprovalIdcsCreatedBy> idcsCreatedBies;
    private String idcsEndpoint;
    /**
     * @return The User or App who modified the Resource
     * 
     */
    private List<GetDomainsMyCompletedApprovalIdcsLastModifiedBy> idcsLastModifiedBies;
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
     * @return Justification for approval
     * 
     */
    private String justification;
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    private List<GetDomainsMyCompletedApprovalMeta> metas;
    private String myCompletedApprovalId;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return The time that the Request was created
     * 
     */
    private String requestCreatedTime;
    /**
     * @return Request Details
     * 
     */
    private String requestDetails;
    /**
     * @return The Unique Identifier of the request.
     * 
     */
    private String requestId;
    /**
     * @return The Oracle Cloud Infrastructure Unique Identifier of the request.
     * 
     */
    private String requestOcid;
    /**
     * @return Requested Resource display name
     * 
     */
    private String resourceDisplayName;
    /**
     * @return Requested Resource type
     * 
     */
    private String resourceType;
    private @Nullable String resourceTypeSchemaVersion;
    /**
     * @return The time that the user responded to the Approval
     * 
     */
    private String responseTime;
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    private List<String> schemas;
    /**
     * @return Status of the approver&#39;s response on the approval
     * 
     */
    private String status;
    /**
     * @return A list of tags on this resource.
     * 
     */
    private List<GetDomainsMyCompletedApprovalTag> tags;
    /**
     * @return Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    private String tenancyOcid;

    private GetDomainsMyCompletedApprovalResult() {}
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
     * @return Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public String domainOcid() {
        return this.domainOcid;
    }
    /**
     * @return Time by when ApprovalWorkflowInstance expires
     * 
     */
    public String expires() {
        return this.expires;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The User or App who created the Resource
     * 
     */
    public List<GetDomainsMyCompletedApprovalIdcsCreatedBy> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * @return The User or App who modified the Resource
     * 
     */
    public List<GetDomainsMyCompletedApprovalIdcsLastModifiedBy> idcsLastModifiedBies() {
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
     * @return Justification for approval
     * 
     */
    public String justification() {
        return this.justification;
    }
    /**
     * @return A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public List<GetDomainsMyCompletedApprovalMeta> metas() {
        return this.metas;
    }
    public String myCompletedApprovalId() {
        return this.myCompletedApprovalId;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The time that the Request was created
     * 
     */
    public String requestCreatedTime() {
        return this.requestCreatedTime;
    }
    /**
     * @return Request Details
     * 
     */
    public String requestDetails() {
        return this.requestDetails;
    }
    /**
     * @return The Unique Identifier of the request.
     * 
     */
    public String requestId() {
        return this.requestId;
    }
    /**
     * @return The Oracle Cloud Infrastructure Unique Identifier of the request.
     * 
     */
    public String requestOcid() {
        return this.requestOcid;
    }
    /**
     * @return Requested Resource display name
     * 
     */
    public String resourceDisplayName() {
        return this.resourceDisplayName;
    }
    /**
     * @return Requested Resource type
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }
    /**
     * @return The time that the user responded to the Approval
     * 
     */
    public String responseTime() {
        return this.responseTime;
    }
    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public List<String> schemas() {
        return this.schemas;
    }
    /**
     * @return Status of the approver&#39;s response on the approval
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return A list of tags on this resource.
     * 
     */
    public List<GetDomainsMyCompletedApprovalTag> tags() {
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

    public static Builder builder(GetDomainsMyCompletedApprovalResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String authorization;
        private String compartmentOcid;
        private Boolean deleteInProgress;
        private String domainOcid;
        private String expires;
        private String id;
        private List<GetDomainsMyCompletedApprovalIdcsCreatedBy> idcsCreatedBies;
        private String idcsEndpoint;
        private List<GetDomainsMyCompletedApprovalIdcsLastModifiedBy> idcsLastModifiedBies;
        private String idcsLastUpgradedInRelease;
        private List<String> idcsPreventedOperations;
        private String justification;
        private List<GetDomainsMyCompletedApprovalMeta> metas;
        private String myCompletedApprovalId;
        private String ocid;
        private String requestCreatedTime;
        private String requestDetails;
        private String requestId;
        private String requestOcid;
        private String resourceDisplayName;
        private String resourceType;
        private @Nullable String resourceTypeSchemaVersion;
        private String responseTime;
        private List<String> schemas;
        private String status;
        private List<GetDomainsMyCompletedApprovalTag> tags;
        private String tenancyOcid;
        public Builder() {}
        public Builder(GetDomainsMyCompletedApprovalResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authorization = defaults.authorization;
    	      this.compartmentOcid = defaults.compartmentOcid;
    	      this.deleteInProgress = defaults.deleteInProgress;
    	      this.domainOcid = defaults.domainOcid;
    	      this.expires = defaults.expires;
    	      this.id = defaults.id;
    	      this.idcsCreatedBies = defaults.idcsCreatedBies;
    	      this.idcsEndpoint = defaults.idcsEndpoint;
    	      this.idcsLastModifiedBies = defaults.idcsLastModifiedBies;
    	      this.idcsLastUpgradedInRelease = defaults.idcsLastUpgradedInRelease;
    	      this.idcsPreventedOperations = defaults.idcsPreventedOperations;
    	      this.justification = defaults.justification;
    	      this.metas = defaults.metas;
    	      this.myCompletedApprovalId = defaults.myCompletedApprovalId;
    	      this.ocid = defaults.ocid;
    	      this.requestCreatedTime = defaults.requestCreatedTime;
    	      this.requestDetails = defaults.requestDetails;
    	      this.requestId = defaults.requestId;
    	      this.requestOcid = defaults.requestOcid;
    	      this.resourceDisplayName = defaults.resourceDisplayName;
    	      this.resourceType = defaults.resourceType;
    	      this.resourceTypeSchemaVersion = defaults.resourceTypeSchemaVersion;
    	      this.responseTime = defaults.responseTime;
    	      this.schemas = defaults.schemas;
    	      this.status = defaults.status;
    	      this.tags = defaults.tags;
    	      this.tenancyOcid = defaults.tenancyOcid;
        }

        @CustomType.Setter
        public Builder authorization(@Nullable String authorization) {

            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentOcid(String compartmentOcid) {
            if (compartmentOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "compartmentOcid");
            }
            this.compartmentOcid = compartmentOcid;
            return this;
        }
        @CustomType.Setter
        public Builder deleteInProgress(Boolean deleteInProgress) {
            if (deleteInProgress == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "deleteInProgress");
            }
            this.deleteInProgress = deleteInProgress;
            return this;
        }
        @CustomType.Setter
        public Builder domainOcid(String domainOcid) {
            if (domainOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "domainOcid");
            }
            this.domainOcid = domainOcid;
            return this;
        }
        @CustomType.Setter
        public Builder expires(String expires) {
            if (expires == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "expires");
            }
            this.expires = expires;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder idcsCreatedBies(List<GetDomainsMyCompletedApprovalIdcsCreatedBy> idcsCreatedBies) {
            if (idcsCreatedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "idcsCreatedBies");
            }
            this.idcsCreatedBies = idcsCreatedBies;
            return this;
        }
        public Builder idcsCreatedBies(GetDomainsMyCompletedApprovalIdcsCreatedBy... idcsCreatedBies) {
            return idcsCreatedBies(List.of(idcsCreatedBies));
        }
        @CustomType.Setter
        public Builder idcsEndpoint(String idcsEndpoint) {
            if (idcsEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "idcsEndpoint");
            }
            this.idcsEndpoint = idcsEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder idcsLastModifiedBies(List<GetDomainsMyCompletedApprovalIdcsLastModifiedBy> idcsLastModifiedBies) {
            if (idcsLastModifiedBies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "idcsLastModifiedBies");
            }
            this.idcsLastModifiedBies = idcsLastModifiedBies;
            return this;
        }
        public Builder idcsLastModifiedBies(GetDomainsMyCompletedApprovalIdcsLastModifiedBy... idcsLastModifiedBies) {
            return idcsLastModifiedBies(List.of(idcsLastModifiedBies));
        }
        @CustomType.Setter
        public Builder idcsLastUpgradedInRelease(String idcsLastUpgradedInRelease) {
            if (idcsLastUpgradedInRelease == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "idcsLastUpgradedInRelease");
            }
            this.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            return this;
        }
        @CustomType.Setter
        public Builder idcsPreventedOperations(List<String> idcsPreventedOperations) {
            if (idcsPreventedOperations == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "idcsPreventedOperations");
            }
            this.idcsPreventedOperations = idcsPreventedOperations;
            return this;
        }
        public Builder idcsPreventedOperations(String... idcsPreventedOperations) {
            return idcsPreventedOperations(List.of(idcsPreventedOperations));
        }
        @CustomType.Setter
        public Builder justification(String justification) {
            if (justification == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "justification");
            }
            this.justification = justification;
            return this;
        }
        @CustomType.Setter
        public Builder metas(List<GetDomainsMyCompletedApprovalMeta> metas) {
            if (metas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "metas");
            }
            this.metas = metas;
            return this;
        }
        public Builder metas(GetDomainsMyCompletedApprovalMeta... metas) {
            return metas(List.of(metas));
        }
        @CustomType.Setter
        public Builder myCompletedApprovalId(String myCompletedApprovalId) {
            if (myCompletedApprovalId == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "myCompletedApprovalId");
            }
            this.myCompletedApprovalId = myCompletedApprovalId;
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            if (ocid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "ocid");
            }
            this.ocid = ocid;
            return this;
        }
        @CustomType.Setter
        public Builder requestCreatedTime(String requestCreatedTime) {
            if (requestCreatedTime == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "requestCreatedTime");
            }
            this.requestCreatedTime = requestCreatedTime;
            return this;
        }
        @CustomType.Setter
        public Builder requestDetails(String requestDetails) {
            if (requestDetails == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "requestDetails");
            }
            this.requestDetails = requestDetails;
            return this;
        }
        @CustomType.Setter
        public Builder requestId(String requestId) {
            if (requestId == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "requestId");
            }
            this.requestId = requestId;
            return this;
        }
        @CustomType.Setter
        public Builder requestOcid(String requestOcid) {
            if (requestOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "requestOcid");
            }
            this.requestOcid = requestOcid;
            return this;
        }
        @CustomType.Setter
        public Builder resourceDisplayName(String resourceDisplayName) {
            if (resourceDisplayName == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "resourceDisplayName");
            }
            this.resourceDisplayName = resourceDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {

            this.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder responseTime(String responseTime) {
            if (responseTime == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "responseTime");
            }
            this.responseTime = responseTime;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<String> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "schemas");
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
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder tags(List<GetDomainsMyCompletedApprovalTag> tags) {
            if (tags == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "tags");
            }
            this.tags = tags;
            return this;
        }
        public Builder tags(GetDomainsMyCompletedApprovalTag... tags) {
            return tags(List.of(tags));
        }
        @CustomType.Setter
        public Builder tenancyOcid(String tenancyOcid) {
            if (tenancyOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyCompletedApprovalResult", "tenancyOcid");
            }
            this.tenancyOcid = tenancyOcid;
            return this;
        }
        public GetDomainsMyCompletedApprovalResult build() {
            final var _resultValue = new GetDomainsMyCompletedApprovalResult();
            _resultValue.authorization = authorization;
            _resultValue.compartmentOcid = compartmentOcid;
            _resultValue.deleteInProgress = deleteInProgress;
            _resultValue.domainOcid = domainOcid;
            _resultValue.expires = expires;
            _resultValue.id = id;
            _resultValue.idcsCreatedBies = idcsCreatedBies;
            _resultValue.idcsEndpoint = idcsEndpoint;
            _resultValue.idcsLastModifiedBies = idcsLastModifiedBies;
            _resultValue.idcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            _resultValue.idcsPreventedOperations = idcsPreventedOperations;
            _resultValue.justification = justification;
            _resultValue.metas = metas;
            _resultValue.myCompletedApprovalId = myCompletedApprovalId;
            _resultValue.ocid = ocid;
            _resultValue.requestCreatedTime = requestCreatedTime;
            _resultValue.requestDetails = requestDetails;
            _resultValue.requestId = requestId;
            _resultValue.requestOcid = requestOcid;
            _resultValue.resourceDisplayName = resourceDisplayName;
            _resultValue.resourceType = resourceType;
            _resultValue.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            _resultValue.responseTime = responseTime;
            _resultValue.schemas = schemas;
            _resultValue.status = status;
            _resultValue.tags = tags;
            _resultValue.tenancyOcid = tenancyOcid;
            return _resultValue;
        }
    }
}
