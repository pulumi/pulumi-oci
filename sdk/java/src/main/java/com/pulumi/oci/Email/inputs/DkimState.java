// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DkimState extends com.pulumi.resources.ResourceArgs {

    public static final DkimState Empty = new DkimState();

    /**
     * The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
     * 
     */
    @Import(name="cnameRecordValue")
    private @Nullable Output<String> cnameRecordValue;

    /**
     * @return The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
     * 
     */
    public Optional<Output<String>> cnameRecordValue() {
        return Optional.ofNullable(this.cnameRecordValue);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A string that describes the details about the DKIM. It does not have to be unique, and you can change it. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A string that describes the details about the DKIM. It does not have to be unique, and you can change it. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue.
     * 
     */
    @Import(name="dnsSubdomainName")
    private @Nullable Output<String> dnsSubdomainName;

    /**
     * @return The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue.
     * 
     */
    public Optional<Output<String>> dnsSubdomainName() {
        return Optional.ofNullable(this.dnsSubdomainName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain for this DKIM.
     * 
     */
    @Import(name="emailDomainId")
    private @Nullable Output<String> emailDomainId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain for this DKIM.
     * 
     */
    public Optional<Output<String>> emailDomainId() {
        return Optional.ofNullable(this.emailDomainId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Indicates whether the DKIM was imported.
     * 
     */
    @Import(name="isImported")
    private @Nullable Output<Boolean> isImported;

    /**
     * @return Indicates whether the DKIM was imported.
     * 
     */
    public Optional<Output<Boolean>> isImported() {
        return Optional.ofNullable(this.isImported);
    }

    /**
     * Length of the RSA key used in the DKIM.
     * 
     */
    @Import(name="keyLength")
    private @Nullable Output<Integer> keyLength;

    /**
     * @return Length of the RSA key used in the DKIM.
     * 
     */
    public Optional<Output<Integer>> keyLength() {
        return Optional.ofNullable(this.keyLength);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The DKIM selector. This selector is required to be globally unique for this email domain. If you do not provide the selector, we will generate one for you. If you do provide the selector, we suggest adding a short region indicator to differentiate from your signing of emails in other regions you might be subscribed to. Selectors limited to ASCII characters can use alphanumeric, dash (&#34;-&#34;), and dot (&#34;.&#34;) characters. Non-ASCII selector names should adopt IDNA2008 normalization (RFC 5891-5892).
     * 
     * Avoid entering confidential information.
     * 
     * Example: `mydomain-phx-20210228`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The DKIM selector. This selector is required to be globally unique for this email domain. If you do not provide the selector, we will generate one for you. If you do provide the selector, we suggest adding a short region indicator to differentiate from your signing of emails in other regions you might be subscribed to. Selectors limited to ASCII characters can use alphanumeric, dash (&#34;-&#34;), and dot (&#34;.&#34;) characters. Non-ASCII selector names should adopt IDNA2008 normalization (RFC 5891-5892).
     * 
     * Avoid entering confidential information.
     * 
     * Example: `mydomain-phx-20210228`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The DKIM RSA Private Key in Privacy-Enhanced Mail (PEM) format. It is a text-based representation of the private key used for signing email messages.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="privateKey")
    private @Nullable Output<String> privateKey;

    /**
     * @return The DKIM RSA Private Key in Privacy-Enhanced Mail (PEM) format. It is a text-based representation of the private key used for signing email messages.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> privateKey() {
        return Optional.ofNullable(this.privateKey);
    }

    /**
     * The current state of the DKIM.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the DKIM.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME cannot be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. You can also use this if you have an existing procedure to directly provision TXT records for DKIM. Many DNS APIs require you to break this string into segments of fewer than 255 characters.
     * 
     */
    @Import(name="txtRecordValue")
    private @Nullable Output<String> txtRecordValue;

    /**
     * @return The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME cannot be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. You can also use this if you have an existing procedure to directly provision TXT records for DKIM. Many DNS APIs require you to break this string into segments of fewer than 255 characters.
     * 
     */
    public Optional<Output<String>> txtRecordValue() {
        return Optional.ofNullable(this.txtRecordValue);
    }

    private DkimState() {}

    private DkimState(DkimState $) {
        this.cnameRecordValue = $.cnameRecordValue;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.dnsSubdomainName = $.dnsSubdomainName;
        this.emailDomainId = $.emailDomainId;
        this.freeformTags = $.freeformTags;
        this.isImported = $.isImported;
        this.keyLength = $.keyLength;
        this.lifecycleDetails = $.lifecycleDetails;
        this.name = $.name;
        this.privateKey = $.privateKey;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.txtRecordValue = $.txtRecordValue;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DkimState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DkimState $;

        public Builder() {
            $ = new DkimState();
        }

        public Builder(DkimState defaults) {
            $ = new DkimState(Objects.requireNonNull(defaults));
        }

        /**
         * @param cnameRecordValue The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
         * 
         * @return builder
         * 
         */
        public Builder cnameRecordValue(@Nullable Output<String> cnameRecordValue) {
            $.cnameRecordValue = cnameRecordValue;
            return this;
        }

        /**
         * @param cnameRecordValue The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
         * 
         * @return builder
         * 
         */
        public Builder cnameRecordValue(String cnameRecordValue) {
            return cnameRecordValue(Output.of(cnameRecordValue));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A string that describes the details about the DKIM. It does not have to be unique, and you can change it. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A string that describes the details about the DKIM. It does not have to be unique, and you can change it. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param dnsSubdomainName The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue.
         * 
         * @return builder
         * 
         */
        public Builder dnsSubdomainName(@Nullable Output<String> dnsSubdomainName) {
            $.dnsSubdomainName = dnsSubdomainName;
            return this;
        }

        /**
         * @param dnsSubdomainName The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue.
         * 
         * @return builder
         * 
         */
        public Builder dnsSubdomainName(String dnsSubdomainName) {
            return dnsSubdomainName(Output.of(dnsSubdomainName));
        }

        /**
         * @param emailDomainId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain for this DKIM.
         * 
         * @return builder
         * 
         */
        public Builder emailDomainId(@Nullable Output<String> emailDomainId) {
            $.emailDomainId = emailDomainId;
            return this;
        }

        /**
         * @param emailDomainId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain for this DKIM.
         * 
         * @return builder
         * 
         */
        public Builder emailDomainId(String emailDomainId) {
            return emailDomainId(Output.of(emailDomainId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isImported Indicates whether the DKIM was imported.
         * 
         * @return builder
         * 
         */
        public Builder isImported(@Nullable Output<Boolean> isImported) {
            $.isImported = isImported;
            return this;
        }

        /**
         * @param isImported Indicates whether the DKIM was imported.
         * 
         * @return builder
         * 
         */
        public Builder isImported(Boolean isImported) {
            return isImported(Output.of(isImported));
        }

        /**
         * @param keyLength Length of the RSA key used in the DKIM.
         * 
         * @return builder
         * 
         */
        public Builder keyLength(@Nullable Output<Integer> keyLength) {
            $.keyLength = keyLength;
            return this;
        }

        /**
         * @param keyLength Length of the RSA key used in the DKIM.
         * 
         * @return builder
         * 
         */
        public Builder keyLength(Integer keyLength) {
            return keyLength(Output.of(keyLength));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param name The DKIM selector. This selector is required to be globally unique for this email domain. If you do not provide the selector, we will generate one for you. If you do provide the selector, we suggest adding a short region indicator to differentiate from your signing of emails in other regions you might be subscribed to. Selectors limited to ASCII characters can use alphanumeric, dash (&#34;-&#34;), and dot (&#34;.&#34;) characters. Non-ASCII selector names should adopt IDNA2008 normalization (RFC 5891-5892).
         * 
         * Avoid entering confidential information.
         * 
         * Example: `mydomain-phx-20210228`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The DKIM selector. This selector is required to be globally unique for this email domain. If you do not provide the selector, we will generate one for you. If you do provide the selector, we suggest adding a short region indicator to differentiate from your signing of emails in other regions you might be subscribed to. Selectors limited to ASCII characters can use alphanumeric, dash (&#34;-&#34;), and dot (&#34;.&#34;) characters. Non-ASCII selector names should adopt IDNA2008 normalization (RFC 5891-5892).
         * 
         * Avoid entering confidential information.
         * 
         * Example: `mydomain-phx-20210228`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param privateKey The DKIM RSA Private Key in Privacy-Enhanced Mail (PEM) format. It is a text-based representation of the private key used for signing email messages.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder privateKey(@Nullable Output<String> privateKey) {
            $.privateKey = privateKey;
            return this;
        }

        /**
         * @param privateKey The DKIM RSA Private Key in Privacy-Enhanced Mail (PEM) format. It is a text-based representation of the private key used for signing email messages.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder privateKey(String privateKey) {
            return privateKey(Output.of(privateKey));
        }

        /**
         * @param state The current state of the DKIM.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the DKIM.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.  Example: `2021-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, &#34;YYYY-MM-ddThh:mmZ&#34;.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param txtRecordValue The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME cannot be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. You can also use this if you have an existing procedure to directly provision TXT records for DKIM. Many DNS APIs require you to break this string into segments of fewer than 255 characters.
         * 
         * @return builder
         * 
         */
        public Builder txtRecordValue(@Nullable Output<String> txtRecordValue) {
            $.txtRecordValue = txtRecordValue;
            return this;
        }

        /**
         * @param txtRecordValue The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME cannot be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. You can also use this if you have an existing procedure to directly provision TXT records for DKIM. Many DNS APIs require you to break this string into segments of fewer than 255 characters.
         * 
         * @return builder
         * 
         */
        public Builder txtRecordValue(String txtRecordValue) {
            return txtRecordValue(Output.of(txtRecordValue));
        }

        public DkimState build() {
            return $;
        }
    }

}
