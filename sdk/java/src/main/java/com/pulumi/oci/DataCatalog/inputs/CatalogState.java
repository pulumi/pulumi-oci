// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CatalogState extends com.pulumi.resources.ResourceArgs {

    public static final CatalogState Empty = new CatalogState();

    /**
     * (Updatable) The list of private reverse connection endpoints attached to the catalog
     * 
     */
    @Import(name="attachedCatalogPrivateEndpoints")
    private @Nullable Output<List<String>> attachedCatalogPrivateEndpoints;

    /**
     * @return (Updatable) The list of private reverse connection endpoints attached to the catalog
     * 
     */
    public Optional<Output<List<String>>> attachedCatalogPrivateEndpoints() {
        return Optional.ofNullable(this.attachedCatalogPrivateEndpoints);
    }

    /**
     * (Updatable) Compartment identifier.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment identifier.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Data catalog identifier.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Data catalog identifier.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * An message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return An message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;Failed&#39; state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
     * 
     */
    @Import(name="numberOfObjects")
    private @Nullable Output<Integer> numberOfObjects;

    /**
     * @return The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
     * 
     */
    public Optional<Output<Integer>> numberOfObjects() {
        return Optional.ofNullable(this.numberOfObjects);
    }

    /**
     * The REST front endpoint URL to the data catalog instance.
     * 
     */
    @Import(name="serviceApiUrl")
    private @Nullable Output<String> serviceApiUrl;

    /**
     * @return The REST front endpoint URL to the data catalog instance.
     * 
     */
    public Optional<Output<String>> serviceApiUrl() {
        return Optional.ofNullable(this.serviceApiUrl);
    }

    /**
     * The console front endpoint URL to the data catalog instance.
     * 
     */
    @Import(name="serviceConsoleUrl")
    private @Nullable Output<String> serviceConsoleUrl;

    /**
     * @return The console front endpoint URL to the data catalog instance.
     * 
     */
    public Optional<Output<String>> serviceConsoleUrl() {
        return Optional.ofNullable(this.serviceConsoleUrl);
    }

    /**
     * The current state of the data catalog resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the data catalog resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private CatalogState() {}

    private CatalogState(CatalogState $) {
        this.attachedCatalogPrivateEndpoints = $.attachedCatalogPrivateEndpoints;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.numberOfObjects = $.numberOfObjects;
        this.serviceApiUrl = $.serviceApiUrl;
        this.serviceConsoleUrl = $.serviceConsoleUrl;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CatalogState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CatalogState $;

        public Builder() {
            $ = new CatalogState();
        }

        public Builder(CatalogState defaults) {
            $ = new CatalogState(Objects.requireNonNull(defaults));
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(@Nullable Output<List<String>> attachedCatalogPrivateEndpoints) {
            $.attachedCatalogPrivateEndpoints = attachedCatalogPrivateEndpoints;
            return this;
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(List<String> attachedCatalogPrivateEndpoints) {
            return attachedCatalogPrivateEndpoints(Output.of(attachedCatalogPrivateEndpoints));
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(String... attachedCatalogPrivateEndpoints) {
            return attachedCatalogPrivateEndpoints(List.of(attachedCatalogPrivateEndpoints));
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Data catalog identifier.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Data catalog identifier.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param lifecycleDetails An message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;Failed&#39; state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails An message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in &#39;Failed&#39; state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param numberOfObjects The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
         * 
         * @return builder
         * 
         */
        public Builder numberOfObjects(@Nullable Output<Integer> numberOfObjects) {
            $.numberOfObjects = numberOfObjects;
            return this;
        }

        /**
         * @param numberOfObjects The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
         * 
         * @return builder
         * 
         */
        public Builder numberOfObjects(Integer numberOfObjects) {
            return numberOfObjects(Output.of(numberOfObjects));
        }

        /**
         * @param serviceApiUrl The REST front endpoint URL to the data catalog instance.
         * 
         * @return builder
         * 
         */
        public Builder serviceApiUrl(@Nullable Output<String> serviceApiUrl) {
            $.serviceApiUrl = serviceApiUrl;
            return this;
        }

        /**
         * @param serviceApiUrl The REST front endpoint URL to the data catalog instance.
         * 
         * @return builder
         * 
         */
        public Builder serviceApiUrl(String serviceApiUrl) {
            return serviceApiUrl(Output.of(serviceApiUrl));
        }

        /**
         * @param serviceConsoleUrl The console front endpoint URL to the data catalog instance.
         * 
         * @return builder
         * 
         */
        public Builder serviceConsoleUrl(@Nullable Output<String> serviceConsoleUrl) {
            $.serviceConsoleUrl = serviceConsoleUrl;
            return this;
        }

        /**
         * @param serviceConsoleUrl The console front endpoint URL to the data catalog instance.
         * 
         * @return builder
         * 
         */
        public Builder serviceConsoleUrl(String serviceConsoleUrl) {
            return serviceConsoleUrl(Output.of(serviceConsoleUrl));
        }

        /**
         * @param state The current state of the data catalog resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the data catalog resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public CatalogState build() {
            return $;
        }
    }

}
