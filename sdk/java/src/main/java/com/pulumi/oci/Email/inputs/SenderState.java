// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SenderState extends com.pulumi.resources.ResourceArgs {

    public static final SenderState Empty = new SenderState();

    /**
     * (Updatable) The OCID of the compartment that contains the sender.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the sender.
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
     * The email address of the sender.
     * 
     */
    @Import(name="emailAddress")
    private @Nullable Output<String> emailAddress;

    /**
     * @return The email address of the sender.
     * 
     */
    public Optional<Output<String>> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }

    /**
     * The email domain used to assert responsibility for emails sent from this sender.
     * 
     */
    @Import(name="emailDomainId")
    private @Nullable Output<String> emailDomainId;

    /**
     * @return The email domain used to assert responsibility for emails sent from this sender.
     * 
     */
    public Optional<Output<String>> emailDomainId() {
        return Optional.ofNullable(this.emailDomainId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    @Import(name="isSpf")
    private @Nullable Output<Boolean> isSpf;

    /**
     * @return Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    public Optional<Output<Boolean>> isSpf() {
        return Optional.ofNullable(this.isSpf);
    }

    /**
     * The current status of the approved sender.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current status of the approved sender.
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
     * The date and time the approved sender was added in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the approved sender was added in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private SenderState() {}

    private SenderState(SenderState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.emailAddress = $.emailAddress;
        this.emailDomainId = $.emailDomainId;
        this.freeformTags = $.freeformTags;
        this.isSpf = $.isSpf;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SenderState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SenderState $;

        public Builder() {
            $ = new SenderState();
        }

        public Builder(SenderState defaults) {
            $ = new SenderState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the sender.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the sender.
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
         * @param emailAddress The email address of the sender.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(@Nullable Output<String> emailAddress) {
            $.emailAddress = emailAddress;
            return this;
        }

        /**
         * @param emailAddress The email address of the sender.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(String emailAddress) {
            return emailAddress(Output.of(emailAddress));
        }

        /**
         * @param emailDomainId The email domain used to assert responsibility for emails sent from this sender.
         * 
         * @return builder
         * 
         */
        public Builder emailDomainId(@Nullable Output<String> emailDomainId) {
            $.emailDomainId = emailDomainId;
            return this;
        }

        /**
         * @param emailDomainId The email domain used to assert responsibility for emails sent from this sender.
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
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
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
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isSpf Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
         * 
         * @return builder
         * 
         */
        public Builder isSpf(@Nullable Output<Boolean> isSpf) {
            $.isSpf = isSpf;
            return this;
        }

        /**
         * @param isSpf Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
         * 
         * @return builder
         * 
         */
        public Builder isSpf(Boolean isSpf) {
            return isSpf(Output.of(isSpf));
        }

        /**
         * @param state The current status of the approved sender.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current status of the approved sender.
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
         * @param timeCreated The date and time the approved sender was added in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the approved sender was added in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public SenderState build() {
            return $;
        }
    }

}
