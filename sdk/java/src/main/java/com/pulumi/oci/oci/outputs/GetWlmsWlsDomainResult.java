// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetWlmsWlsDomainConfiguration;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWlmsWlsDomainResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The WebLogic domain configuration.
     * 
     */
    private List<GetWlmsWlsDomainConfiguration> configurations;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name that does not have to be unique and is changeable.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Whether or not the terms of use agreement has been accepted for the WebLogic domain.
     * 
     */
    private Boolean isAcceptedTermsAndConditions;
    /**
     * @return A message that describes the current state of the WebLogic domain in more detail. For example, it can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The middleware type on the administration server of the WebLogic domain.
     * 
     */
    private String middlewareType;
    /**
     * @return The patch readiness status of the WebLogic domain.
     * 
     */
    private String patchReadinessStatus;
    /**
     * @return The current state of the WebLogic service domain.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the WebLogic domain was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the WebLogic domain was updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return The version of the WebLogic domain.
     * 
     */
    private String weblogicVersion;
    private String wlsDomainId;

    private GetWlmsWlsDomainResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The WebLogic domain configuration.
     * 
     */
    public List<GetWlmsWlsDomainConfiguration> configurations() {
        return this.configurations;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name that does not have to be unique and is changeable.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether or not the terms of use agreement has been accepted for the WebLogic domain.
     * 
     */
    public Boolean isAcceptedTermsAndConditions() {
        return this.isAcceptedTermsAndConditions;
    }
    /**
     * @return A message that describes the current state of the WebLogic domain in more detail. For example, it can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The middleware type on the administration server of the WebLogic domain.
     * 
     */
    public String middlewareType() {
        return this.middlewareType;
    }
    /**
     * @return The patch readiness status of the WebLogic domain.
     * 
     */
    public String patchReadinessStatus() {
        return this.patchReadinessStatus;
    }
    /**
     * @return The current state of the WebLogic service domain.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the WebLogic domain was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the WebLogic domain was updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The version of the WebLogic domain.
     * 
     */
    public String weblogicVersion() {
        return this.weblogicVersion;
    }
    public String wlsDomainId() {
        return this.wlsDomainId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWlmsWlsDomainResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetWlmsWlsDomainConfiguration> configurations;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isAcceptedTermsAndConditions;
        private String lifecycleDetails;
        private String middlewareType;
        private String patchReadinessStatus;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String weblogicVersion;
        private String wlsDomainId;
        public Builder() {}
        public Builder(GetWlmsWlsDomainResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurations = defaults.configurations;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isAcceptedTermsAndConditions = defaults.isAcceptedTermsAndConditions;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.middlewareType = defaults.middlewareType;
    	      this.patchReadinessStatus = defaults.patchReadinessStatus;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.weblogicVersion = defaults.weblogicVersion;
    	      this.wlsDomainId = defaults.wlsDomainId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configurations(List<GetWlmsWlsDomainConfiguration> configurations) {
            if (configurations == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "configurations");
            }
            this.configurations = configurations;
            return this;
        }
        public Builder configurations(GetWlmsWlsDomainConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAcceptedTermsAndConditions(Boolean isAcceptedTermsAndConditions) {
            if (isAcceptedTermsAndConditions == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "isAcceptedTermsAndConditions");
            }
            this.isAcceptedTermsAndConditions = isAcceptedTermsAndConditions;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder middlewareType(String middlewareType) {
            if (middlewareType == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "middlewareType");
            }
            this.middlewareType = middlewareType;
            return this;
        }
        @CustomType.Setter
        public Builder patchReadinessStatus(String patchReadinessStatus) {
            if (patchReadinessStatus == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "patchReadinessStatus");
            }
            this.patchReadinessStatus = patchReadinessStatus;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder weblogicVersion(String weblogicVersion) {
            if (weblogicVersion == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "weblogicVersion");
            }
            this.weblogicVersion = weblogicVersion;
            return this;
        }
        @CustomType.Setter
        public Builder wlsDomainId(String wlsDomainId) {
            if (wlsDomainId == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainResult", "wlsDomainId");
            }
            this.wlsDomainId = wlsDomainId;
            return this;
        }
        public GetWlmsWlsDomainResult build() {
            final var _resultValue = new GetWlmsWlsDomainResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.configurations = configurations;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isAcceptedTermsAndConditions = isAcceptedTermsAndConditions;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.middlewareType = middlewareType;
            _resultValue.patchReadinessStatus = patchReadinessStatus;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.weblogicVersion = weblogicVersion;
            _resultValue.wlsDomainId = wlsDomainId;
            return _resultValue;
        }
    }
}
