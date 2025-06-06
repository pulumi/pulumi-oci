// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedListState extends com.pulumi.resources.ResourceArgs {

    public static final ManagedListState Empty = new ManagedListState();

    /**
     * (Updatable) Compartment OCID
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment OCID
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Managed list description
     * 
     * Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Managed list description
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Managed list display name.
     * 
     * Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Managed list display name.
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Provider of the managed list feed
     * 
     */
    @Import(name="feedProvider")
    private @Nullable Output<String> feedProvider;

    /**
     * @return Provider of the managed list feed
     * 
     */
    public Optional<Output<String>> feedProvider() {
        return Optional.ofNullable(this.feedProvider);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     * Avoid entering confidential information.
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     * Avoid entering confidential information.
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Is this list editable?
     * 
     */
    @Import(name="isEditable")
    private @Nullable Output<Boolean> isEditable;

    /**
     * @return Is this list editable?
     * 
     */
    public Optional<Output<Boolean>> isEditable() {
        return Optional.ofNullable(this.isEditable);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    @Import(name="lifecyleDetails")
    private @Nullable Output<String> lifecyleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    public Optional<Output<String>> lifecyleDetails() {
        return Optional.ofNullable(this.lifecyleDetails);
    }

    /**
     * (Updatable) List of items in the managed list
     * 
     */
    @Import(name="listItems")
    private @Nullable Output<List<String>> listItems;

    /**
     * @return (Updatable) List of items in the managed list
     * 
     */
    public Optional<Output<List<String>>> listItems() {
        return Optional.ofNullable(this.listItems);
    }

    /**
     * Type of information stored in the list
     * 
     */
    @Import(name="listType")
    private @Nullable Output<String> listType;

    /**
     * @return Type of information stored in the list
     * 
     */
    public Optional<Output<String>> listType() {
        return Optional.ofNullable(this.listType);
    }

    /**
     * OCID of the source managed list
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="sourceManagedListId")
    private @Nullable Output<String> sourceManagedListId;

    /**
     * @return OCID of the source managed list
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> sourceManagedListId() {
        return Optional.ofNullable(this.sourceManagedListId);
    }

    /**
     * The current lifecycle state of the resource
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the resource
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the managed list was last updated. Format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the managed list was last updated. Format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ManagedListState() {}

    private ManagedListState(ManagedListState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.feedProvider = $.feedProvider;
        this.freeformTags = $.freeformTags;
        this.isEditable = $.isEditable;
        this.lifecyleDetails = $.lifecyleDetails;
        this.listItems = $.listItems;
        this.listType = $.listType;
        this.sourceManagedListId = $.sourceManagedListId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedListState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedListState $;

        public Builder() {
            $ = new ManagedListState();
        }

        public Builder(ManagedListState defaults) {
            $ = new ManagedListState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Managed list description
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Managed list description
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Managed list display name.
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Managed list display name.
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param feedProvider Provider of the managed list feed
         * 
         * @return builder
         * 
         */
        public Builder feedProvider(@Nullable Output<String> feedProvider) {
            $.feedProvider = feedProvider;
            return this;
        }

        /**
         * @param feedProvider Provider of the managed list feed
         * 
         * @return builder
         * 
         */
        public Builder feedProvider(String feedProvider) {
            return feedProvider(Output.of(feedProvider));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isEditable Is this list editable?
         * 
         * @return builder
         * 
         */
        public Builder isEditable(@Nullable Output<Boolean> isEditable) {
            $.isEditable = isEditable;
            return this;
        }

        /**
         * @param isEditable Is this list editable?
         * 
         * @return builder
         * 
         */
        public Builder isEditable(Boolean isEditable) {
            return isEditable(Output.of(isEditable));
        }

        /**
         * @param lifecyleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
         * 
         * @return builder
         * 
         */
        public Builder lifecyleDetails(@Nullable Output<String> lifecyleDetails) {
            $.lifecyleDetails = lifecyleDetails;
            return this;
        }

        /**
         * @param lifecyleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
         * 
         * @return builder
         * 
         */
        public Builder lifecyleDetails(String lifecyleDetails) {
            return lifecyleDetails(Output.of(lifecyleDetails));
        }

        /**
         * @param listItems (Updatable) List of items in the managed list
         * 
         * @return builder
         * 
         */
        public Builder listItems(@Nullable Output<List<String>> listItems) {
            $.listItems = listItems;
            return this;
        }

        /**
         * @param listItems (Updatable) List of items in the managed list
         * 
         * @return builder
         * 
         */
        public Builder listItems(List<String> listItems) {
            return listItems(Output.of(listItems));
        }

        /**
         * @param listItems (Updatable) List of items in the managed list
         * 
         * @return builder
         * 
         */
        public Builder listItems(String... listItems) {
            return listItems(List.of(listItems));
        }

        /**
         * @param listType Type of information stored in the list
         * 
         * @return builder
         * 
         */
        public Builder listType(@Nullable Output<String> listType) {
            $.listType = listType;
            return this;
        }

        /**
         * @param listType Type of information stored in the list
         * 
         * @return builder
         * 
         */
        public Builder listType(String listType) {
            return listType(Output.of(listType));
        }

        /**
         * @param sourceManagedListId OCID of the source managed list
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sourceManagedListId(@Nullable Output<String> sourceManagedListId) {
            $.sourceManagedListId = sourceManagedListId;
            return this;
        }

        /**
         * @param sourceManagedListId OCID of the source managed list
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sourceManagedListId(String sourceManagedListId) {
            return sourceManagedListId(Output.of(sourceManagedListId));
        }

        /**
         * @param state The current lifecycle state of the resource
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the resource
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The date and time the managed list was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the managed list was created. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the managed list was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the managed list was last updated. Format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ManagedListState build() {
            return $;
        }
    }

}
