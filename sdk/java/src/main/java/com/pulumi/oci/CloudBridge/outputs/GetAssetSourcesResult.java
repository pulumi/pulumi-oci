// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudBridge.outputs.GetAssetSourcesAssetSourceCollection;
import com.pulumi.oci.CloudBridge.outputs.GetAssetSourcesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAssetSourcesResult {
    /**
     * @return The list of asset_source_collection.
     * 
     */
    private List<GetAssetSourcesAssetSourceCollection> assetSourceCollections;
    private @Nullable String assetSourceId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the resource.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name for the asset source. Does not have to be unique, and it&#39;s mutable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetAssetSourcesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the asset source.
     * 
     */
    private @Nullable String state;

    private GetAssetSourcesResult() {}
    /**
     * @return The list of asset_source_collection.
     * 
     */
    public List<GetAssetSourcesAssetSourceCollection> assetSourceCollections() {
        return this.assetSourceCollections;
    }
    public Optional<String> assetSourceId() {
        return Optional.ofNullable(this.assetSourceId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the resource.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name for the asset source. Does not have to be unique, and it&#39;s mutable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetAssetSourcesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current state of the asset source.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetSourcesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAssetSourcesAssetSourceCollection> assetSourceCollections;
        private @Nullable String assetSourceId;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetAssetSourcesFilter> filters;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetAssetSourcesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.assetSourceCollections = defaults.assetSourceCollections;
    	      this.assetSourceId = defaults.assetSourceId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder assetSourceCollections(List<GetAssetSourcesAssetSourceCollection> assetSourceCollections) {
            this.assetSourceCollections = Objects.requireNonNull(assetSourceCollections);
            return this;
        }
        public Builder assetSourceCollections(GetAssetSourcesAssetSourceCollection... assetSourceCollections) {
            return assetSourceCollections(List.of(assetSourceCollections));
        }
        @CustomType.Setter
        public Builder assetSourceId(@Nullable String assetSourceId) {
            this.assetSourceId = assetSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetAssetSourcesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAssetSourcesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetAssetSourcesResult build() {
            final var o = new GetAssetSourcesResult();
            o.assetSourceCollections = assetSourceCollections;
            o.assetSourceId = assetSourceId;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.state = state;
            return o;
        }
    }
}