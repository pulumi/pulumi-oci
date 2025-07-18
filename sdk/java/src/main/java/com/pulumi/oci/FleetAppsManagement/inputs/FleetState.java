// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetCredentialArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetDetailsArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetNotificationPreferenceArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetPropertyArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetResourceArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetResourceSelectionArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FleetState extends com.pulumi.resources.ResourceArgs {

    public static final FleetState Empty = new FleetState();

    /**
     * (Updatable) compartment OCID
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) compartment OCID
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Credentials associated with the Fleet.
     * 
     */
    @Import(name="credentials")
    private @Nullable Output<List<FleetCredentialArgs>> credentials;

    /**
     * @return Credentials associated with the Fleet.
     * 
     */
    public Optional<Output<List<FleetCredentialArgs>>> credentials() {
        return Optional.ofNullable(this.credentials);
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
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * Fleet Type
     * 
     */
    @Import(name="details")
    private @Nullable Output<FleetDetailsArgs> details;

    /**
     * @return Fleet Type
     * 
     */
    public Optional<Output<FleetDetailsArgs>> details() {
        return Optional.ofNullable(this.details);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
     * 
     */
    @Import(name="environmentType")
    private @Nullable Output<String> environmentType;

    /**
     * @return Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
     * 
     */
    public Optional<Output<String>> environmentType() {
        return Optional.ofNullable(this.environmentType);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
     * 
     */
    @Import(name="isTargetAutoConfirm")
    private @Nullable Output<Boolean> isTargetAutoConfirm;

    /**
     * @return (Updatable) A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
     * 
     */
    public Optional<Output<Boolean>> isTargetAutoConfirm() {
        return Optional.ofNullable(this.isTargetAutoConfirm);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) Notification Preferences associated with the Fleet.
     * 
     */
    @Import(name="notificationPreferences")
    private @Nullable Output<List<FleetNotificationPreferenceArgs>> notificationPreferences;

    /**
     * @return (Updatable) Notification Preferences associated with the Fleet.
     * 
     */
    public Optional<Output<List<FleetNotificationPreferenceArgs>>> notificationPreferences() {
        return Optional.ofNullable(this.notificationPreferences);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
     * 
     */
    @Import(name="parentFleetId")
    private @Nullable Output<String> parentFleetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
     * 
     */
    public Optional<Output<String>> parentFleetId() {
        return Optional.ofNullable(this.parentFleetId);
    }

    /**
     * (Updatable) Products associated with the Fleet.
     * 
     */
    @Import(name="products")
    private @Nullable Output<List<String>> products;

    /**
     * @return (Updatable) Products associated with the Fleet.
     * 
     */
    public Optional<Output<List<String>>> products() {
        return Optional.ofNullable(this.products);
    }

    /**
     * Properties associated with the Fleet.
     * 
     */
    @Import(name="properties")
    private @Nullable Output<List<FleetPropertyArgs>> properties;

    /**
     * @return Properties associated with the Fleet.
     * 
     */
    public Optional<Output<List<FleetPropertyArgs>>> properties() {
        return Optional.ofNullable(this.properties);
    }

    /**
     * Associated region
     * 
     */
    @Import(name="resourceRegion")
    private @Nullable Output<String> resourceRegion;

    /**
     * @return Associated region
     * 
     */
    public Optional<Output<String>> resourceRegion() {
        return Optional.ofNullable(this.resourceRegion);
    }

    /**
     * (Updatable) Resource Selection Type
     * 
     */
    @Import(name="resourceSelection")
    private @Nullable Output<FleetResourceSelectionArgs> resourceSelection;

    /**
     * @return (Updatable) Resource Selection Type
     * 
     */
    public Optional<Output<FleetResourceSelectionArgs>> resourceSelection() {
        return Optional.ofNullable(this.resourceSelection);
    }

    /**
     * Resources associated with the Fleet if resourceSelectionType is MANUAL.
     * 
     */
    @Import(name="resources")
    private @Nullable Output<List<FleetResourceArgs>> resources;

    /**
     * @return Resources associated with the Fleet if resourceSelectionType is MANUAL.
     * 
     */
    public Optional<Output<List<FleetResourceArgs>>> resources() {
        return Optional.ofNullable(this.resources);
    }

    /**
     * The lifecycle state of the Fleet.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The lifecycle state of the Fleet.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private FleetState() {}

    private FleetState(FleetState $) {
        this.compartmentId = $.compartmentId;
        this.credentials = $.credentials;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.details = $.details;
        this.displayName = $.displayName;
        this.environmentType = $.environmentType;
        this.freeformTags = $.freeformTags;
        this.isTargetAutoConfirm = $.isTargetAutoConfirm;
        this.lifecycleDetails = $.lifecycleDetails;
        this.notificationPreferences = $.notificationPreferences;
        this.parentFleetId = $.parentFleetId;
        this.products = $.products;
        this.properties = $.properties;
        this.resourceRegion = $.resourceRegion;
        this.resourceSelection = $.resourceSelection;
        this.resources = $.resources;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FleetState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FleetState $;

        public Builder() {
            $ = new FleetState();
        }

        public Builder(FleetState defaults) {
            $ = new FleetState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param credentials Credentials associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder credentials(@Nullable Output<List<FleetCredentialArgs>> credentials) {
            $.credentials = credentials;
            return this;
        }

        /**
         * @param credentials Credentials associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder credentials(List<FleetCredentialArgs> credentials) {
            return credentials(Output.of(credentials));
        }

        /**
         * @param credentials Credentials associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder credentials(FleetCredentialArgs... credentials) {
            return credentials(List.of(credentials));
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
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param details Fleet Type
         * 
         * @return builder
         * 
         */
        public Builder details(@Nullable Output<FleetDetailsArgs> details) {
            $.details = details;
            return this;
        }

        /**
         * @param details Fleet Type
         * 
         * @return builder
         * 
         */
        public Builder details(FleetDetailsArgs details) {
            return details(Output.of(details));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param environmentType Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
         * 
         * @return builder
         * 
         */
        public Builder environmentType(@Nullable Output<String> environmentType) {
            $.environmentType = environmentType;
            return this;
        }

        /**
         * @param environmentType Environment Type associated with the Fleet. Applicable for ENVIRONMENT fleet types.
         * 
         * @return builder
         * 
         */
        public Builder environmentType(String environmentType) {
            return environmentType(Output.of(environmentType));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
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
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isTargetAutoConfirm (Updatable) A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
         * 
         * @return builder
         * 
         */
        public Builder isTargetAutoConfirm(@Nullable Output<Boolean> isTargetAutoConfirm) {
            $.isTargetAutoConfirm = isTargetAutoConfirm;
            return this;
        }

        /**
         * @param isTargetAutoConfirm (Updatable) A value that represents if auto-confirming of the targets can be enabled. This will allow targets to be auto-confirmed in the fleet without manual intervention.
         * 
         * @return builder
         * 
         */
        public Builder isTargetAutoConfirm(Boolean isTargetAutoConfirm) {
            return isTargetAutoConfirm(Output.of(isTargetAutoConfirm));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param notificationPreferences (Updatable) Notification Preferences associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder notificationPreferences(@Nullable Output<List<FleetNotificationPreferenceArgs>> notificationPreferences) {
            $.notificationPreferences = notificationPreferences;
            return this;
        }

        /**
         * @param notificationPreferences (Updatable) Notification Preferences associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder notificationPreferences(List<FleetNotificationPreferenceArgs> notificationPreferences) {
            return notificationPreferences(Output.of(notificationPreferences));
        }

        /**
         * @param notificationPreferences (Updatable) Notification Preferences associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder notificationPreferences(FleetNotificationPreferenceArgs... notificationPreferences) {
            return notificationPreferences(List.of(notificationPreferences));
        }

        /**
         * @param parentFleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
         * 
         * @return builder
         * 
         */
        public Builder parentFleetId(@Nullable Output<String> parentFleetId) {
            $.parentFleetId = parentFleetId;
            return this;
        }

        /**
         * @param parentFleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet that would be the parent for this fleet.
         * 
         * @return builder
         * 
         */
        public Builder parentFleetId(String parentFleetId) {
            return parentFleetId(Output.of(parentFleetId));
        }

        /**
         * @param products (Updatable) Products associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder products(@Nullable Output<List<String>> products) {
            $.products = products;
            return this;
        }

        /**
         * @param products (Updatable) Products associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder products(List<String> products) {
            return products(Output.of(products));
        }

        /**
         * @param products (Updatable) Products associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder products(String... products) {
            return products(List.of(products));
        }

        /**
         * @param properties Properties associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder properties(@Nullable Output<List<FleetPropertyArgs>> properties) {
            $.properties = properties;
            return this;
        }

        /**
         * @param properties Properties associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder properties(List<FleetPropertyArgs> properties) {
            return properties(Output.of(properties));
        }

        /**
         * @param properties Properties associated with the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder properties(FleetPropertyArgs... properties) {
            return properties(List.of(properties));
        }

        /**
         * @param resourceRegion Associated region
         * 
         * @return builder
         * 
         */
        public Builder resourceRegion(@Nullable Output<String> resourceRegion) {
            $.resourceRegion = resourceRegion;
            return this;
        }

        /**
         * @param resourceRegion Associated region
         * 
         * @return builder
         * 
         */
        public Builder resourceRegion(String resourceRegion) {
            return resourceRegion(Output.of(resourceRegion));
        }

        /**
         * @param resourceSelection (Updatable) Resource Selection Type
         * 
         * @return builder
         * 
         */
        public Builder resourceSelection(@Nullable Output<FleetResourceSelectionArgs> resourceSelection) {
            $.resourceSelection = resourceSelection;
            return this;
        }

        /**
         * @param resourceSelection (Updatable) Resource Selection Type
         * 
         * @return builder
         * 
         */
        public Builder resourceSelection(FleetResourceSelectionArgs resourceSelection) {
            return resourceSelection(Output.of(resourceSelection));
        }

        /**
         * @param resources Resources associated with the Fleet if resourceSelectionType is MANUAL.
         * 
         * @return builder
         * 
         */
        public Builder resources(@Nullable Output<List<FleetResourceArgs>> resources) {
            $.resources = resources;
            return this;
        }

        /**
         * @param resources Resources associated with the Fleet if resourceSelectionType is MANUAL.
         * 
         * @return builder
         * 
         */
        public Builder resources(List<FleetResourceArgs> resources) {
            return resources(Output.of(resources));
        }

        /**
         * @param resources Resources associated with the Fleet if resourceSelectionType is MANUAL.
         * 
         * @return builder
         * 
         */
        public Builder resources(FleetResourceArgs... resources) {
            return resources(List.of(resources));
        }

        /**
         * @param state The lifecycle state of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The lifecycle state of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time this resource was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time this resource was created. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time this resource was last updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time this resource was last updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public FleetState build() {
            return $;
        }
    }

}
