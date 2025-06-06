// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetAutonomousDatabasesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousDatabasesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabasesPlainArgs Empty = new GetAutonomousDatabasesPlainArgs();

    /**
     * The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousContainerDatabaseId")
    private @Nullable String autonomousContainerDatabaseId;

    /**
     * @return The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<String> autonomousContainerDatabaseId() {
        return Optional.ofNullable(this.autonomousContainerDatabaseId);
    }

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
     * A filter to return only autonomous database resources that match the specified dbVersion.
     * 
     */
    @Import(name="dbVersion")
    private @Nullable String dbVersion;

    /**
     * @return A filter to return only autonomous database resources that match the specified dbVersion.
     * 
     */
    public Optional<String> dbVersion() {
        return Optional.ofNullable(this.dbVersion);
    }

    /**
     * A filter to return only autonomous database resources that match the specified workload type.
     * 
     */
    @Import(name="dbWorkload")
    private @Nullable String dbWorkload;

    /**
     * @return A filter to return only autonomous database resources that match the specified workload type.
     * 
     */
    public Optional<String> dbWorkload() {
        return Optional.ofNullable(this.dbWorkload);
    }

    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetAutonomousDatabasesFilter> filters;

    public Optional<List<GetAutonomousDatabasesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given Infrastructure Type.
     * 
     */
    @Import(name="infrastructureType")
    private @Nullable String infrastructureType;

    /**
     * @return A filter to return only resources that match the given Infrastructure Type.
     * 
     */
    public Optional<String> infrastructureType() {
        return Optional.ofNullable(this.infrastructureType);
    }

    /**
     * A filter to return only resources that have Data Guard enabled.
     * 
     */
    @Import(name="isDataGuardEnabled")
    private @Nullable Boolean isDataGuardEnabled;

    /**
     * @return A filter to return only resources that have Data Guard enabled.
     * 
     */
    public Optional<Boolean> isDataGuardEnabled() {
        return Optional.ofNullable(this.isDataGuardEnabled);
    }

    /**
     * Filter on the value of the resource&#39;s &#39;isFreeTier&#39; property. A value of `true` returns only Always Free resources. A value of `false` excludes Always Free resources from the returned results. Omitting this parameter returns both Always Free and paid resources.
     * 
     */
    @Import(name="isFreeTier")
    private @Nullable Boolean isFreeTier;

    /**
     * @return Filter on the value of the resource&#39;s &#39;isFreeTier&#39; property. A value of `true` returns only Always Free resources. A value of `false` excludes Always Free resources from the returned results. Omitting this parameter returns both Always Free and paid resources.
     * 
     */
    public Optional<Boolean> isFreeTier() {
        return Optional.ofNullable(this.isFreeTier);
    }

    /**
     * Filter on the value of the resource&#39;s &#39;isRefreshableClone&#39; property. A value of `true` returns only refreshable clones. A value of `false` excludes refreshable clones from the returned results. Omitting this parameter returns both refreshable clones and databases that are not refreshable clones.
     * 
     */
    @Import(name="isRefreshableClone")
    private @Nullable Boolean isRefreshableClone;

    /**
     * @return Filter on the value of the resource&#39;s &#39;isRefreshableClone&#39; property. A value of `true` returns only refreshable clones. A value of `false` excludes refreshable clones from the returned results. Omitting this parameter returns both refreshable clones and databases that are not refreshable clones.
     * 
     */
    public Optional<Boolean> isRefreshableClone() {
        return Optional.ofNullable(this.isRefreshableClone);
    }

    /**
     * Filter if the resource is the resource pool leader. A value of `true` returns only resource pool leader.
     * 
     */
    @Import(name="isResourcePoolLeader")
    private @Nullable Boolean isResourcePoolLeader;

    /**
     * @return Filter if the resource is the resource pool leader. A value of `true` returns only resource pool leader.
     * 
     */
    public Optional<Boolean> isResourcePoolLeader() {
        return Optional.ofNullable(this.isResourcePoolLeader);
    }

    @Import(name="lifecycleStateNotEqualTo")
    private @Nullable String lifecycleStateNotEqualTo;

    public Optional<String> lifecycleStateNotEqualTo() {
        return Optional.ofNullable(this.lifecycleStateNotEqualTo);
    }

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resourcepool Leader Autonomous Database.
     * 
     */
    @Import(name="resourcePoolLeaderId")
    private @Nullable String resourcePoolLeaderId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resourcepool Leader Autonomous Database.
     * 
     */
    public Optional<String> resourcePoolLeaderId() {
        return Optional.ofNullable(this.resourcePoolLeaderId);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAutonomousDatabasesPlainArgs() {}

    private GetAutonomousDatabasesPlainArgs(GetAutonomousDatabasesPlainArgs $) {
        this.autonomousContainerDatabaseId = $.autonomousContainerDatabaseId;
        this.compartmentId = $.compartmentId;
        this.dbVersion = $.dbVersion;
        this.dbWorkload = $.dbWorkload;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.infrastructureType = $.infrastructureType;
        this.isDataGuardEnabled = $.isDataGuardEnabled;
        this.isFreeTier = $.isFreeTier;
        this.isRefreshableClone = $.isRefreshableClone;
        this.isResourcePoolLeader = $.isResourcePoolLeader;
        this.lifecycleStateNotEqualTo = $.lifecycleStateNotEqualTo;
        this.resourcePoolLeaderId = $.resourcePoolLeaderId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabasesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabasesPlainArgs $;

        public Builder() {
            $ = new GetAutonomousDatabasesPlainArgs();
        }

        public Builder(GetAutonomousDatabasesPlainArgs defaults) {
            $ = new GetAutonomousDatabasesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousContainerDatabaseId The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousContainerDatabaseId(@Nullable String autonomousContainerDatabaseId) {
            $.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
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
         * @param dbVersion A filter to return only autonomous database resources that match the specified dbVersion.
         * 
         * @return builder
         * 
         */
        public Builder dbVersion(@Nullable String dbVersion) {
            $.dbVersion = dbVersion;
            return this;
        }

        /**
         * @param dbWorkload A filter to return only autonomous database resources that match the specified workload type.
         * 
         * @return builder
         * 
         */
        public Builder dbWorkload(@Nullable String dbWorkload) {
            $.dbWorkload = dbWorkload;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetAutonomousDatabasesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAutonomousDatabasesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param infrastructureType A filter to return only resources that match the given Infrastructure Type.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureType(@Nullable String infrastructureType) {
            $.infrastructureType = infrastructureType;
            return this;
        }

        /**
         * @param isDataGuardEnabled A filter to return only resources that have Data Guard enabled.
         * 
         * @return builder
         * 
         */
        public Builder isDataGuardEnabled(@Nullable Boolean isDataGuardEnabled) {
            $.isDataGuardEnabled = isDataGuardEnabled;
            return this;
        }

        /**
         * @param isFreeTier Filter on the value of the resource&#39;s &#39;isFreeTier&#39; property. A value of `true` returns only Always Free resources. A value of `false` excludes Always Free resources from the returned results. Omitting this parameter returns both Always Free and paid resources.
         * 
         * @return builder
         * 
         */
        public Builder isFreeTier(@Nullable Boolean isFreeTier) {
            $.isFreeTier = isFreeTier;
            return this;
        }

        /**
         * @param isRefreshableClone Filter on the value of the resource&#39;s &#39;isRefreshableClone&#39; property. A value of `true` returns only refreshable clones. A value of `false` excludes refreshable clones from the returned results. Omitting this parameter returns both refreshable clones and databases that are not refreshable clones.
         * 
         * @return builder
         * 
         */
        public Builder isRefreshableClone(@Nullable Boolean isRefreshableClone) {
            $.isRefreshableClone = isRefreshableClone;
            return this;
        }

        /**
         * @param isResourcePoolLeader Filter if the resource is the resource pool leader. A value of `true` returns only resource pool leader.
         * 
         * @return builder
         * 
         */
        public Builder isResourcePoolLeader(@Nullable Boolean isResourcePoolLeader) {
            $.isResourcePoolLeader = isResourcePoolLeader;
            return this;
        }

        public Builder lifecycleStateNotEqualTo(@Nullable String lifecycleStateNotEqualTo) {
            $.lifecycleStateNotEqualTo = lifecycleStateNotEqualTo;
            return this;
        }

        /**
         * @param resourcePoolLeaderId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resourcepool Leader Autonomous Database.
         * 
         * @return builder
         * 
         */
        public Builder resourcePoolLeaderId(@Nullable String resourcePoolLeaderId) {
            $.resourcePoolLeaderId = resourcePoolLeaderId;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetAutonomousDatabasesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAutonomousDatabasesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
