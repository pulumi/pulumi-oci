// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDbNodesDbNode;
import com.pulumi.oci.Database.outputs.GetDbNodesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDbNodesResult {
    private String compartmentId;
    /**
     * @return The list of db_nodes.
     * 
     */
    private List<GetDbNodesDbNode> dbNodes;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
     * 
     */
    private @Nullable String dbServerId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     * 
     */
    private @Nullable String dbSystemId;
    private @Nullable List<GetDbNodesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the database node.
     * 
     */
    private @Nullable String state;
    private @Nullable String vmClusterId;

    private GetDbNodesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of db_nodes.
     * 
     */
    public List<GetDbNodesDbNode> dbNodes() {
        return this.dbNodes;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
     * 
     */
    public Optional<String> dbServerId() {
        return Optional.ofNullable(this.dbServerId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     * 
     */
    public Optional<String> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }
    public List<GetDbNodesFilter> filters() {
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
     * @return The current state of the database node.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> vmClusterId() {
        return Optional.ofNullable(this.vmClusterId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbNodesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDbNodesDbNode> dbNodes;
        private @Nullable String dbServerId;
        private @Nullable String dbSystemId;
        private @Nullable List<GetDbNodesFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String vmClusterId;
        public Builder() {}
        public Builder(GetDbNodesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbNodes = defaults.dbNodes;
    	      this.dbServerId = defaults.dbServerId;
    	      this.dbSystemId = defaults.dbSystemId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.vmClusterId = defaults.vmClusterId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder dbNodes(List<GetDbNodesDbNode> dbNodes) {
            this.dbNodes = Objects.requireNonNull(dbNodes);
            return this;
        }
        public Builder dbNodes(GetDbNodesDbNode... dbNodes) {
            return dbNodes(List.of(dbNodes));
        }
        @CustomType.Setter
        public Builder dbServerId(@Nullable String dbServerId) {
            this.dbServerId = dbServerId;
            return this;
        }
        @CustomType.Setter
        public Builder dbSystemId(@Nullable String dbSystemId) {
            this.dbSystemId = dbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDbNodesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDbNodesFilter... filters) {
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
        @CustomType.Setter
        public Builder vmClusterId(@Nullable String vmClusterId) {
            this.vmClusterId = vmClusterId;
            return this;
        }
        public GetDbNodesResult build() {
            final var o = new GetDbNodesResult();
            o.compartmentId = compartmentId;
            o.dbNodes = dbNodes;
            o.dbServerId = dbServerId;
            o.dbSystemId = dbSystemId;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.vmClusterId = vmClusterId;
            return o;
        }
    }
}