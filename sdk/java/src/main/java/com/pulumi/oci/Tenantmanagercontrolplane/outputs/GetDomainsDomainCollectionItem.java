// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDomainsDomainCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The domain name.
     * 
     */
    private String domainName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the domain.
     * 
     */
    private String id;
    private Boolean isGovernanceEnabled;
    /**
     * @return The OCID of the tenancy that has started the registration process for this domain.
     * 
     */
    private String ownerId;
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    private String state;
    /**
     * @return The status of the domain.
     * 
     */
    private String status;
    private String subscriptionEmail;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Date-time when this domain was created. An RFC 3339-formatted date and time string.
     * 
     */
    private String timeCreated;
    /**
     * @return Date-time when this domain was last updated. An RFC 3339-formatted date and time string.
     * 
     */
    private String timeUpdated;
    /**
     * @return The code that the owner of the domain will need to add as a TXT record to their domain.
     * 
     */
    private String txtRecord;

    private GetDomainsDomainCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The domain name.
     * 
     */
    public String domainName() {
        return this.domainName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the domain.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isGovernanceEnabled() {
        return this.isGovernanceEnabled;
    }
    /**
     * @return The OCID of the tenancy that has started the registration process for this domain.
     * 
     */
    public String ownerId() {
        return this.ownerId;
    }
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The status of the domain.
     * 
     */
    public String status() {
        return this.status;
    }
    public String subscriptionEmail() {
        return this.subscriptionEmail;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Date-time when this domain was created. An RFC 3339-formatted date and time string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Date-time when this domain was last updated. An RFC 3339-formatted date and time string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The code that the owner of the domain will need to add as a TXT record to their domain.
     * 
     */
    public String txtRecord() {
        return this.txtRecord;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsDomainCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String domainName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isGovernanceEnabled;
        private String ownerId;
        private String state;
        private String status;
        private String subscriptionEmail;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String txtRecord;
        public Builder() {}
        public Builder(GetDomainsDomainCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.domainName = defaults.domainName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isGovernanceEnabled = defaults.isGovernanceEnabled;
    	      this.ownerId = defaults.ownerId;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.subscriptionEmail = defaults.subscriptionEmail;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.txtRecord = defaults.txtRecord;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder domainName(String domainName) {
            if (domainName == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "domainName");
            }
            this.domainName = domainName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isGovernanceEnabled(Boolean isGovernanceEnabled) {
            if (isGovernanceEnabled == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "isGovernanceEnabled");
            }
            this.isGovernanceEnabled = isGovernanceEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder ownerId(String ownerId) {
            if (ownerId == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "ownerId");
            }
            this.ownerId = ownerId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionEmail(String subscriptionEmail) {
            if (subscriptionEmail == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "subscriptionEmail");
            }
            this.subscriptionEmail = subscriptionEmail;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder txtRecord(String txtRecord) {
            if (txtRecord == null) {
              throw new MissingRequiredPropertyException("GetDomainsDomainCollectionItem", "txtRecord");
            }
            this.txtRecord = txtRecord;
            return this;
        }
        public GetDomainsDomainCollectionItem build() {
            final var _resultValue = new GetDomainsDomainCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.domainName = domainName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isGovernanceEnabled = isGovernanceEnabled;
            _resultValue.ownerId = ownerId;
            _resultValue.state = state;
            _resultValue.status = status;
            _resultValue.subscriptionEmail = subscriptionEmail;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.txtRecord = txtRecord;
            return _resultValue;
        }
    }
}
