// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.GetReplicasFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetReplicasPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReplicasPlainArgs Empty = new GetReplicasPlainArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable String dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<String> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    /**
     * A filter to return only the resource matching the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetReplicasFilter> filters;

    public Optional<List<GetReplicasFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="replicaId")
    private @Nullable String replicaId;

    /**
     * @return The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<String> replicaId() {
        return Optional.ofNullable(this.replicaId);
    }

    /**
     * The LifecycleState of the read replica.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The LifecycleState of the read replica.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetReplicasPlainArgs() {}

    private GetReplicasPlainArgs(GetReplicasPlainArgs $) {
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
    public static Builder builder(GetReplicasPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReplicasPlainArgs $;

        public Builder() {
            $ = new GetReplicasPlainArgs();
        }

        public Builder(GetReplicasPlainArgs defaults) {
            $ = new GetReplicasPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable String dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param displayName A filter to return only the resource matching the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetReplicasFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetReplicasFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param replicaId The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder replicaId(@Nullable String replicaId) {
            $.replicaId = replicaId;
            return this;
        }

        /**
         * @param state The LifecycleState of the read replica.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetReplicasPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}