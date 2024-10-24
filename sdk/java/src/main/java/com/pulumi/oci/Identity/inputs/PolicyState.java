// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PolicyState extends com.pulumi.resources.ResourceArgs {

    public static final PolicyState Empty = new PolicyState();

    /**
     * @deprecated
     * The &#39;ETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'ETag' field has been deprecated and may be removed in a future version. Do not use this field. */
    @Import(name="ETag")
    private @Nullable Output<String> ETag;

    /**
     * @deprecated
     * The &#39;ETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'ETag' field has been deprecated and may be removed in a future version. Do not use this field. */
    public Optional<Output<String>> ETag() {
        return Optional.ofNullable(this.ETag);
    }

    /**
     * The OCID of the compartment containing the policy (either the tenancy or another compartment).
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the policy (either the tenancy or another compartment).
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description you assign to the policy during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description you assign to the policy during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Import(name="inactiveState")
    private @Nullable Output<String> inactiveState;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Optional<Output<String>> inactiveState() {
        return Optional.ofNullable(this.inactiveState);
    }

    /**
     * @deprecated
     * The &#39;lastUpdateETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'lastUpdateETag' field has been deprecated and may be removed in a future version. Do not use this field. */
    @Import(name="lastUpdateETag")
    private @Nullable Output<String> lastUpdateETag;

    /**
     * @deprecated
     * The &#39;lastUpdateETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'lastUpdateETag' field has been deprecated and may be removed in a future version. Do not use this field. */
    public Optional<Output<String>> lastUpdateETag() {
        return Optional.ofNullable(this.lastUpdateETag);
    }

    /**
     * The name you assign to the policy during creation. The name must be unique across all policies in the tenancy and cannot be changed.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name you assign to the policy during creation. The name must be unique across all policies in the tenancy and cannot be changed.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * @deprecated
     * The &#39;policyHash&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'policyHash' field has been deprecated and may be removed in a future version. Do not use this field. */
    @Import(name="policyHash")
    private @Nullable Output<String> policyHash;

    /**
     * @deprecated
     * The &#39;policyHash&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'policyHash' field has been deprecated and may be removed in a future version. Do not use this field. */
    public Optional<Output<String>> policyHash() {
        return Optional.ofNullable(this.policyHash);
    }

    /**
     * The policy&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The policy&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * (Updatable) An array of policy statements written in the policy language. See [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm) and [Common Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/commonpolicies.htm).
     * 
     */
    @Import(name="statements")
    private @Nullable Output<List<String>> statements;

    /**
     * @return (Updatable) An array of policy statements written in the policy language. See [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm) and [Common Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/commonpolicies.htm).
     * 
     */
    public Optional<Output<List<String>>> statements() {
        return Optional.ofNullable(this.statements);
    }

    /**
     * Date and time the policy was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Date and time the policy was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) The version of the policy. If null or set to an empty string, when a request comes in for authorization, the policy will be evaluated according to the current behavior of the services at that moment. If set to a particular date (YYYY-MM-DD), the policy will be evaluated according to the behavior of the services on that date.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="versionDate")
    private @Nullable Output<String> versionDate;

    /**
     * @return (Updatable) The version of the policy. If null or set to an empty string, when a request comes in for authorization, the policy will be evaluated according to the current behavior of the services at that moment. If set to a particular date (YYYY-MM-DD), the policy will be evaluated according to the behavior of the services on that date.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> versionDate() {
        return Optional.ofNullable(this.versionDate);
    }

    private PolicyState() {}

    private PolicyState(PolicyState $) {
        this.ETag = $.ETag;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.inactiveState = $.inactiveState;
        this.lastUpdateETag = $.lastUpdateETag;
        this.name = $.name;
        this.policyHash = $.policyHash;
        this.state = $.state;
        this.statements = $.statements;
        this.timeCreated = $.timeCreated;
        this.versionDate = $.versionDate;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PolicyState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PolicyState $;

        public Builder() {
            $ = new PolicyState();
        }

        public Builder(PolicyState defaults) {
            $ = new PolicyState(Objects.requireNonNull(defaults));
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;ETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'ETag' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder ETag(@Nullable Output<String> ETag) {
            $.ETag = ETag;
            return this;
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;ETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'ETag' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder ETag(String ETag) {
            return ETag(Output.of(ETag));
        }

        /**
         * @param compartmentId The OCID of the compartment containing the policy (either the tenancy or another compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment containing the policy (either the tenancy or another compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description you assign to the policy during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description you assign to the policy during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(@Nullable Output<String> inactiveState) {
            $.inactiveState = inactiveState;
            return this;
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(String inactiveState) {
            return inactiveState(Output.of(inactiveState));
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;lastUpdateETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'lastUpdateETag' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder lastUpdateETag(@Nullable Output<String> lastUpdateETag) {
            $.lastUpdateETag = lastUpdateETag;
            return this;
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;lastUpdateETag&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'lastUpdateETag' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder lastUpdateETag(String lastUpdateETag) {
            return lastUpdateETag(Output.of(lastUpdateETag));
        }

        /**
         * @param name The name you assign to the policy during creation. The name must be unique across all policies in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name you assign to the policy during creation. The name must be unique across all policies in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;policyHash&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'policyHash' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder policyHash(@Nullable Output<String> policyHash) {
            $.policyHash = policyHash;
            return this;
        }

        /**
         * @return builder
         * 
         * @deprecated
         * The &#39;policyHash&#39; field has been deprecated and may be removed in a future version. Do not use this field.
         * 
         */
        @Deprecated /* The 'policyHash' field has been deprecated and may be removed in a future version. Do not use this field. */
        public Builder policyHash(String policyHash) {
            return policyHash(Output.of(policyHash));
        }

        /**
         * @param state The policy&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The policy&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param statements (Updatable) An array of policy statements written in the policy language. See [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm) and [Common Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/commonpolicies.htm).
         * 
         * @return builder
         * 
         */
        public Builder statements(@Nullable Output<List<String>> statements) {
            $.statements = statements;
            return this;
        }

        /**
         * @param statements (Updatable) An array of policy statements written in the policy language. See [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm) and [Common Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/commonpolicies.htm).
         * 
         * @return builder
         * 
         */
        public Builder statements(List<String> statements) {
            return statements(Output.of(statements));
        }

        /**
         * @param statements (Updatable) An array of policy statements written in the policy language. See [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm) and [Common Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/commonpolicies.htm).
         * 
         * @return builder
         * 
         */
        public Builder statements(String... statements) {
            return statements(List.of(statements));
        }

        /**
         * @param timeCreated Date and time the policy was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Date and time the policy was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param versionDate (Updatable) The version of the policy. If null or set to an empty string, when a request comes in for authorization, the policy will be evaluated according to the current behavior of the services at that moment. If set to a particular date (YYYY-MM-DD), the policy will be evaluated according to the behavior of the services on that date.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder versionDate(@Nullable Output<String> versionDate) {
            $.versionDate = versionDate;
            return this;
        }

        /**
         * @param versionDate (Updatable) The version of the policy. If null or set to an empty string, when a request comes in for authorization, the policy will be evaluated according to the current behavior of the services at that moment. If set to a particular date (YYYY-MM-DD), the policy will be evaluated according to the behavior of the services on that date.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder versionDate(String versionDate) {
            return versionDate(Output.of(versionDate));
        }

        public PolicyState build() {
            return $;
        }
    }

}
