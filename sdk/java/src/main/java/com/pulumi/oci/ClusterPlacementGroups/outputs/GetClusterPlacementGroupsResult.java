// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ClusterPlacementGroups.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ClusterPlacementGroups.outputs.GetClusterPlacementGroupsClusterPlacementGroupCollection;
import com.pulumi.oci.ClusterPlacementGroups.outputs.GetClusterPlacementGroupsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetClusterPlacementGroupsResult {
    private @Nullable String ad;
    /**
     * @return The list of cluster_placement_group_collection.
     * 
     */
    private List<GetClusterPlacementGroupsClusterPlacementGroupCollection> clusterPlacementGroupCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the cluster placement group.
     * 
     */
    private @Nullable String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    private @Nullable List<GetClusterPlacementGroupsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group.
     * 
     */
    private @Nullable String id;
    /**
     * @return The user-friendly name of the cluster placement group. The display name for a cluster placement must be unique and you cannot change it. Avoid entering confidential information.
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the ClusterPlacementGroup.
     * 
     */
    private @Nullable String state;

    private GetClusterPlacementGroupsResult() {}
    public Optional<String> ad() {
        return Optional.ofNullable(this.ad);
    }
    /**
     * @return The list of cluster_placement_group_collection.
     * 
     */
    public List<GetClusterPlacementGroupsClusterPlacementGroupCollection> clusterPlacementGroupCollections() {
        return this.clusterPlacementGroupCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the cluster placement group.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetClusterPlacementGroupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The user-friendly name of the cluster placement group. The display name for a cluster placement must be unique and you cannot change it. Avoid entering confidential information.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the ClusterPlacementGroup.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterPlacementGroupsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ad;
        private List<GetClusterPlacementGroupsClusterPlacementGroupCollection> clusterPlacementGroupCollections;
        private @Nullable String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetClusterPlacementGroupsFilter> filters;
        private @Nullable String id;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetClusterPlacementGroupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ad = defaults.ad;
    	      this.clusterPlacementGroupCollections = defaults.clusterPlacementGroupCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder ad(@Nullable String ad) {

            this.ad = ad;
            return this;
        }
        @CustomType.Setter
        public Builder clusterPlacementGroupCollections(List<GetClusterPlacementGroupsClusterPlacementGroupCollection> clusterPlacementGroupCollections) {
            if (clusterPlacementGroupCollections == null) {
              throw new MissingRequiredPropertyException("GetClusterPlacementGroupsResult", "clusterPlacementGroupCollections");
            }
            this.clusterPlacementGroupCollections = clusterPlacementGroupCollections;
            return this;
        }
        public Builder clusterPlacementGroupCollections(GetClusterPlacementGroupsClusterPlacementGroupCollection... clusterPlacementGroupCollections) {
            return clusterPlacementGroupCollections(List.of(clusterPlacementGroupCollections));
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {

            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetClusterPlacementGroupsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetClusterPlacementGroupsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetClusterPlacementGroupsResult build() {
            final var _resultValue = new GetClusterPlacementGroupsResult();
            _resultValue.ad = ad;
            _resultValue.clusterPlacementGroupCollections = clusterPlacementGroupCollections;
            _resultValue.compartmentId = compartmentId;
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
