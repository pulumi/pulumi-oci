// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDkimResult {
    /**
     * @return The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
     * 
     */
    private String cnameRecordValue;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The description of the DKIM. Avoid entering confidential information.
     * 
     */
    private String description;
    private String dkimId;
    /**
     * @return The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue
     * 
     */
    private String dnsSubdomainName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
     * 
     */
    private String emailDomainId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
     * 
     */
    private String name;
    /**
     * @return The current state of the DKIM.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
     * 
     */
    private String timeUpdated;
    /**
     * @return The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME can not be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. This can also be used by customers who have an existing procedure to directly provision TXT records for DKIM. Be aware that many DNS APIs will require you to break this string into segments of less than 255 characters.
     * 
     */
    private String txtRecordValue;

    private GetDkimResult() {}
    /**
     * @return The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
     * 
     */
    public String cnameRecordValue() {
        return this.cnameRecordValue;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the DKIM. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    public String dkimId() {
        return this.dkimId;
    }
    /**
     * @return The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue
     * 
     */
    public String dnsSubdomainName() {
        return this.dnsSubdomainName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
     * 
     */
    public String emailDomainId() {
        return this.emailDomainId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The current state of the DKIM.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME can not be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. This can also be used by customers who have an existing procedure to directly provision TXT records for DKIM. Be aware that many DNS APIs will require you to break this string into segments of less than 255 characters.
     * 
     */
    public String txtRecordValue() {
        return this.txtRecordValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDkimResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String cnameRecordValue;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String dkimId;
        private String dnsSubdomainName;
        private String emailDomainId;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String name;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String txtRecordValue;
        public Builder() {}
        public Builder(GetDkimResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cnameRecordValue = defaults.cnameRecordValue;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.dkimId = defaults.dkimId;
    	      this.dnsSubdomainName = defaults.dnsSubdomainName;
    	      this.emailDomainId = defaults.emailDomainId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.txtRecordValue = defaults.txtRecordValue;
        }

        @CustomType.Setter
        public Builder cnameRecordValue(String cnameRecordValue) {
            this.cnameRecordValue = Objects.requireNonNull(cnameRecordValue);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder dkimId(String dkimId) {
            this.dkimId = Objects.requireNonNull(dkimId);
            return this;
        }
        @CustomType.Setter
        public Builder dnsSubdomainName(String dnsSubdomainName) {
            this.dnsSubdomainName = Objects.requireNonNull(dnsSubdomainName);
            return this;
        }
        @CustomType.Setter
        public Builder emailDomainId(String emailDomainId) {
            this.emailDomainId = Objects.requireNonNull(emailDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder txtRecordValue(String txtRecordValue) {
            this.txtRecordValue = Objects.requireNonNull(txtRecordValue);
            return this;
        }
        public GetDkimResult build() {
            final var o = new GetDkimResult();
            o.cnameRecordValue = cnameRecordValue;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.dkimId = dkimId;
            o.dnsSubdomainName = dnsSubdomainName;
            o.emailDomainId = emailDomainId;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.name = name;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.txtRecordValue = txtRecordValue;
            return o;
        }
    }
}