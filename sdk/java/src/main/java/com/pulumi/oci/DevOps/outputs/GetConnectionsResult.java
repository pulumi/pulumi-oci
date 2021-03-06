// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetConnectionsConnectionCollection;
import com.pulumi.oci.DevOps.outputs.GetConnectionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConnectionsResult {
    /**
     * @return The OCID of the compartment containing the connection.
     * 
     */
    private final @Nullable String compartmentId;
    /**
     * @return The list of connection_collection.
     * 
     */
    private final List<GetConnectionsConnectionCollection> connectionCollections;
    /**
     * @return The type of connection.
     * 
     */
    private final @Nullable String connectionType;
    /**
     * @return Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetConnectionsFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private final @Nullable String id;
    /**
     * @return The OCID of the DevOps project.
     * 
     */
    private final @Nullable String projectId;
    /**
     * @return The current state of the connection.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetConnectionsResult(
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("connectionCollections") List<GetConnectionsConnectionCollection> connectionCollections,
        @CustomType.Parameter("connectionType") @Nullable String connectionType,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetConnectionsFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("projectId") @Nullable String projectId,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.connectionCollections = connectionCollections;
        this.connectionType = connectionType;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.projectId = projectId;
        this.state = state;
    }

    /**
     * @return The OCID of the compartment containing the connection.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The list of connection_collection.
     * 
     */
    public List<GetConnectionsConnectionCollection> connectionCollections() {
        return this.connectionCollections;
    }
    /**
     * @return The type of connection.
     * 
     */
    public Optional<String> connectionType() {
        return Optional.ofNullable(this.connectionType);
    }
    /**
     * @return Connection display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetConnectionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The OCID of the DevOps project.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The current state of the connection.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String compartmentId;
        private List<GetConnectionsConnectionCollection> connectionCollections;
        private @Nullable String connectionType;
        private @Nullable String displayName;
        private @Nullable List<GetConnectionsFilter> filters;
        private @Nullable String id;
        private @Nullable String projectId;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetConnectionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionCollections = defaults.connectionCollections;
    	      this.connectionType = defaults.connectionType;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder connectionCollections(List<GetConnectionsConnectionCollection> connectionCollections) {
            this.connectionCollections = Objects.requireNonNull(connectionCollections);
            return this;
        }
        public Builder connectionCollections(GetConnectionsConnectionCollection... connectionCollections) {
            return connectionCollections(List.of(connectionCollections));
        }
        public Builder connectionType(@Nullable String connectionType) {
            this.connectionType = connectionType;
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetConnectionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetConnectionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder projectId(@Nullable String projectId) {
            this.projectId = projectId;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetConnectionsResult build() {
            return new GetConnectionsResult(compartmentId, connectionCollections, connectionType, displayName, filters, id, projectId, state);
        }
    }
}
