// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.GetReplicasFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetReplicasArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReplicasArgs Empty = new GetReplicasArgs();

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
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable Output<String> dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    /**
     * A filter to return only the resource matching the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetReplicasFilterArgs>> filters;

    public Optional<Output<List<GetReplicasFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="replicaId")
    private @Nullable Output<String> replicaId;

    /**
     * @return The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> replicaId() {
        return Optional.ofNullable(this.replicaId);
    }

    /**
     * The LifecycleState of the read replica.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The LifecycleState of the read replica.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetReplicasArgs() {}

    private GetReplicasArgs(GetReplicasArgs $) {
        this.compartmentId = $.compartmentId;
        this.dbSystemId = $.dbSystemId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.replicaId = $.replicaId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReplicasArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReplicasArgs $;

        public Builder() {
            $ = new GetReplicasArgs();
        }

        public Builder(GetReplicasArgs defaults) {
            $ = new GetReplicasArgs(Objects.requireNonNull(defaults));
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
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        /**
         * @param displayName A filter to return only the resource matching the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resource matching the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetReplicasFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetReplicasFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetReplicasFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param replicaId The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder replicaId(@Nullable Output<String> replicaId) {
            $.replicaId = replicaId;
            return this;
        }

        /**
         * @param replicaId The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder replicaId(String replicaId) {
            return replicaId(Output.of(replicaId));
        }

        /**
         * @param state The LifecycleState of the read replica.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The LifecycleState of the read replica.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetReplicasArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}