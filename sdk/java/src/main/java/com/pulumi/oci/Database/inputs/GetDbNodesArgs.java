// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetDbNodesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbNodesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbNodesArgs Empty = new GetDbNodesArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server.
     * 
     */
    @Import(name="dbServerId")
    private @Nullable Output<String> dbServerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server.
     * 
     */
    public Optional<Output<String>> dbServerId() {
        return Optional.ofNullable(this.dbServerId);
    }

    /**
     * The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable Output<String> dbSystemId;

    /**
     * @return The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
     * 
     */
    public Optional<Output<String>> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDbNodesFilterArgs>> filters;

    public Optional<Output<List<GetDbNodesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     * 
     */
    @Import(name="vmClusterId")
    private @Nullable Output<String> vmClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     * 
     */
    public Optional<Output<String>> vmClusterId() {
        return Optional.ofNullable(this.vmClusterId);
    }

    private GetDbNodesArgs() {}

    private GetDbNodesArgs(GetDbNodesArgs $) {
        this.compartmentId = $.compartmentId;
        this.dbServerId = $.dbServerId;
        this.dbSystemId = $.dbSystemId;
        this.filters = $.filters;
        this.state = $.state;
        this.vmClusterId = $.vmClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbNodesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbNodesArgs $;

        public Builder() {
            $ = new GetDbNodesArgs();
        }

        public Builder(GetDbNodesArgs defaults) {
            $ = new GetDbNodesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dbServerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server.
         * 
         * @return builder
         * 
         */
        public Builder dbServerId(@Nullable Output<String> dbServerId) {
            $.dbServerId = dbServerId;
            return this;
        }

        /**
         * @param dbServerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server.
         * 
         * @return builder
         * 
         */
        public Builder dbServerId(String dbServerId) {
            return dbServerId(Output.of(dbServerId));
        }

        /**
         * @param dbSystemId The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        public Builder filters(@Nullable Output<List<GetDbNodesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDbNodesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDbNodesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vmClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(@Nullable Output<String> vmClusterId) {
            $.vmClusterId = vmClusterId;
            return this;
        }

        /**
         * @param vmClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(String vmClusterId) {
            return vmClusterId(Output.of(vmClusterId));
        }

        public GetDbNodesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDbNodesArgs", "compartmentId");
            }
            return $;
        }
    }

}
