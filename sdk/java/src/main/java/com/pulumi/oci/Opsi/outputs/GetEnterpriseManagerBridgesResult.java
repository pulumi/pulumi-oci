// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection;
import com.pulumi.oci.Opsi.outputs.GetEnterpriseManagerBridgesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetEnterpriseManagerBridgesResult {
    /**
     * @return Compartment identifier of the Enterprise Manager bridge
     * 
     */
    private final @Nullable String compartmentId;
    private final @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    private final @Nullable String displayName;
    /**
     * @return The list of enterprise_manager_bridge_collection.
     * 
     */
    private final List<GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection> enterpriseManagerBridgeCollections;
    private final @Nullable List<GetEnterpriseManagerBridgesFilter> filters;
    /**
     * @return Enterprise Manager bridge identifier
     * 
     */
    private final @Nullable String id;
    /**
     * @return The current state of the Enterprise Manager bridge.
     * 
     */
    private final @Nullable List<String> states;

    @CustomType.Constructor
    private GetEnterpriseManagerBridgesResult(
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("compartmentIdInSubtree") @Nullable Boolean compartmentIdInSubtree,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("enterpriseManagerBridgeCollections") List<GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection> enterpriseManagerBridgeCollections,
        @CustomType.Parameter("filters") @Nullable List<GetEnterpriseManagerBridgesFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("states") @Nullable List<String> states) {
        this.compartmentId = compartmentId;
        this.compartmentIdInSubtree = compartmentIdInSubtree;
        this.displayName = displayName;
        this.enterpriseManagerBridgeCollections = enterpriseManagerBridgeCollections;
        this.filters = filters;
        this.id = id;
        this.states = states;
    }

    /**
     * @return Compartment identifier of the Enterprise Manager bridge
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of enterprise_manager_bridge_collection.
     * 
     */
    public List<GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection> enterpriseManagerBridgeCollections() {
        return this.enterpriseManagerBridgeCollections;
    }
    public List<GetEnterpriseManagerBridgesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Enterprise Manager bridge identifier
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the Enterprise Manager bridge.
     * 
     */
    public List<String> states() {
        return this.states == null ? List.of() : this.states;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEnterpriseManagerBridgesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private List<GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection> enterpriseManagerBridgeCollections;
        private @Nullable List<GetEnterpriseManagerBridgesFilter> filters;
        private @Nullable String id;
        private @Nullable List<String> states;

        public Builder() {
    	      // Empty
        }

        public Builder(GetEnterpriseManagerBridgesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.enterpriseManagerBridgeCollections = defaults.enterpriseManagerBridgeCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.states = defaults.states;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder enterpriseManagerBridgeCollections(List<GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection> enterpriseManagerBridgeCollections) {
            this.enterpriseManagerBridgeCollections = Objects.requireNonNull(enterpriseManagerBridgeCollections);
            return this;
        }
        public Builder enterpriseManagerBridgeCollections(GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollection... enterpriseManagerBridgeCollections) {
            return enterpriseManagerBridgeCollections(List.of(enterpriseManagerBridgeCollections));
        }
        public Builder filters(@Nullable List<GetEnterpriseManagerBridgesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetEnterpriseManagerBridgesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder states(@Nullable List<String> states) {
            this.states = states;
            return this;
        }
        public Builder states(String... states) {
            return states(List.of(states));
        }        public GetEnterpriseManagerBridgesResult build() {
            return new GetEnterpriseManagerBridgesResult(compartmentId, compartmentIdInSubtree, displayName, enterpriseManagerBridgeCollections, filters, id, states);
        }
    }
}
